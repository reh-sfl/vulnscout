"""Local, opt-in Copilot chat backed by the VulnScout stdio MCP server."""

import asyncio
import json
import os
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from flask import Blueprint, current_app, jsonify, request


READ_TOOLS = (
    "get_assessment", "list_assessments_by_vuln", "has_ai_assessment",
    "get_vulnerability", "find_project_id", "find_variant_id",
    "get_merged_context", "get_project_context", "get_custom_assessment",
    "list_custom_assessments",
)
WRITE_TOOLS = (
    "write_assessment", "update_ai_assessment", "update_project_context",
    "update_variant_context", "write_assessment_review",
)
COOKIE = "vulnscout_agent"
PAGES = {"metrics", "packages", "vulnerabilities", "scans", "review", "exports", "settings", "ai"}
agent_blueprint = Blueprint("agent", __name__)


@dataclass
class Conversation:
    token: str | None = None
    session_id: str | None = None
    model: str = "auto"
    usage: dict = field(default_factory=lambda: {"cost": None, "input_tokens": None, "output_tokens": None})
    messages: list[dict[str, str]] = field(default_factory=list)
    last_used: float = field(default_factory=time.monotonic)
    lock: threading.Lock = field(default_factory=threading.Lock)


_conversations: dict[str, Conversation] = {}
_store_lock = threading.Lock()


def _conversation():
    key = request.cookies.get(COOKIE, "")
    with _store_lock:
        expired = [key for key, value in _conversations.items()
                   if time.monotonic() - value.last_used > 3600]
        for old_key in expired:
            del _conversations[old_key]
        if key not in _conversations:
            key = secrets.token_urlsafe(32)
            _conversations[key] = Conversation()
        conversation = _conversations[key]
        conversation.last_used = time.monotonic()
    return key, conversation


def _response(payload, key, status=200):
    response = jsonify(payload)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    response.set_cookie(COOKIE, key, httponly=True, samesite="Strict",
                        secure=request.is_secure, max_age=3600)
    return response


def _access_error():
    if os.getenv("VULNSCOUT_AGENT_ENABLED") != "1":
        return jsonify(error="Agent chat is disabled on this server."), 404
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify(error="Agent chat is available only on localhost."), 403
    if urlsplit(request.host_url).hostname not in ("127.0.0.1", "localhost", "::1"):
        return jsonify(error="Agent chat requires a localhost host."), 403
    origin = request.headers.get("Origin")
    if request.method != "GET" and origin and origin.rstrip("/") != request.host_url.rstrip("/"):
        return jsonify(error="Invalid request origin."), 403
    return None


def _mcp_path():
    value = os.getenv("VULNSCOUT_MCP_SERVER_PATH", "")
    return Path(value).expanduser().resolve() if value else None


def _sdk_client(token):
    from copilot import CopilotClient

    return CopilotClient(github_token=token, use_logged_in_user=token is None,
                         working_directory=str(Path(__file__).resolve().parents[2]))


async def _auth_status(token):
    async with _sdk_client(token) as client:
        status = await client.get_auth_status()
        return {"authenticated": status.isAuthenticated, "login": status.login}


async def _models(token):
    async with _sdk_client(token) as client:
        return [{"id": model.id, "name": model.name} for model in await client.list_models()
                if model.policy is None or model.policy.state == "enabled"]


async def _delete_session(token, session_id):
    async with _sdk_client(token) as client:
        await client.delete_session(session_id)


class UnavailableModelError(ValueError):
    pass


def _session_usage(events):
    from copilot.session_events import AssistantUsageData

    usage = [event.data for event in events if isinstance(event.data, AssistantUsageData)]
    costs = [event.cost for event in usage if event.cost is not None]
    inputs = [event.input_tokens for event in usage if event.input_tokens is not None]
    outputs = [event.output_tokens for event in usage if event.output_tokens is not None]
    return {
        "cost": sum(costs) if costs else None,
        "input_tokens": sum(inputs) if inputs else None,
        "output_tokens": sum(outputs) if outputs else None,
    }


def _add_usage(previous, current):
    return {key: previous[key] if current[key] is None else (previous[key] or 0) + current[key]
            for key in ("cost", "input_tokens", "output_tokens")}


def _bounded_string(value, limit, error):
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError(error)
    return value


def _bounded_strings(values, count, limit, error):
    if not isinstance(values, list) or len(values) > count or any(
        not isinstance(item, str) or len(item) > limit for item in values
    ):
        raise ValueError(error)
    return values


def _bounded_count(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1000000:
        raise ValueError("Invalid selection count.")
    return value


def _scan_option(value):
    if not isinstance(value, bool):
        raise ValueError("Invalid scan option.")
    return value


def _view_context(view):
    if not isinstance(view, dict):
        raise ValueError("Invalid view context.")
    filtered = {}
    for key in (
        "openVulnerabilityId", "search", "section", "selectedProjectId", "selectedProjectName",
        "selectedVariantId", "selectedVariantName", "openScanId", "exportType", "exportMode",
        "exportCategory", "refreshMode",
    ):
        if view.get(key) is not None:
            filtered[key] = _bounded_string(view[key], 200, "Invalid view selection.")
    for key in (
        "visibleVulnerabilityIds", "selectedVulnerabilityIds", "visiblePackageIds", "visibleScanIds",
        "matchingVariantIds", "selectedVariantIds", "selectedExportKeys", "enabledExportDocuments",
        "selectedScanTypes", "selectedRefreshTypes",
    ):
        if view.get(key) is not None:
            filtered[key] = _bounded_strings(
                view[key], 100, 200,
                "Filter the table to 100 vulnerabilities or fewer before sending all displayed IDs.",
            )
    for key in ("visibleCount", "selectionCount"):
        if key in view:
            filtered[key] = _bounded_count(view[key])
    for key in ("hideEmptyScans", "excludeKernel", "excludeNative"):
        if key in view:
            filtered[key] = _scan_option(view[key])
    return filtered


def _validated_context(value):
    if value is None:
        return None
    if not isinstance(value, dict) or value.get("page") not in PAGES:
        raise ValueError("Invalid page context.")
    context = {"page": value["page"]}
    for key in ("projectId", "variantId", "baseVariantId", "compareOperation", "multiOperation"):
        if value.get(key) is not None:
            context[key] = _bounded_string(value[key], 100, "Invalid page scope.")
    if value.get("variantIds") is not None:
        context["variantIds"] = _bounded_strings(value["variantIds"], 50, 100, "Invalid variant selection.")
    if "variantCount" in value:
        context["variantCount"] = _bounded_count(value["variantCount"])
    if value.get("view") is not None:
        context["view"] = _view_context(value["view"])
    return context


async def _reply(conversation, message, allow_writes, path, model):
    from copilot.session import PermissionHandler

    tools = READ_TOOLS + WRITE_TOOLS if allow_writes else READ_TOOLS
    async with _sdk_client(conversation.token) as client:
        models = await client.list_models()
        if model not in {choice.id for choice in models if choice.policy is None or choice.policy.state == "enabled"}:
            raise UnavailableModelError("Selected model is not available for this account.")
        options = {
            "model": model,
            "on_permission_request": PermissionHandler.approve_all,
            "available_tools": [f"mcp:vulnscout-{tool}" for tool in tools],
            "mcp_servers": {"vulnscout": {
                "type": "local", "command": sys.executable,
                "args": [str(path)], "cwd": str(path.parent),
                "env": {"VULNSCOUT_BASE_URL": os.getenv("VULNSCOUT_AGENT_API_URL", "http://localhost:7275")},
                "tools": list(tools),
            }},
            "system_message": {"mode": "append", "content": (
                "You are the VulnScout agent. Use only VulnScout MCP tools for facts and actions. "
                "Explain what you changed. If a tool returns an error, report it; do not invent results."
            )},
            "enable_config_discovery": False,
            "enable_host_git_operations": False,
            "enable_skills": False,
            "enable_file_hooks": False,
        }
        if conversation.session_id:
            session = await client.resume_session(conversation.session_id, **options)
        else:
            session = await client.create_session(**options)
        try:
            live_events = []
            session.on(live_events.append)
            event = await asyncio.wait_for(session.send_and_wait(message), timeout=120)
            if event is None or not event.data.content:
                raise RuntimeError("The agent did not return a response.")
            conversation.session_id = session.session_id
            usage = _add_usage(conversation.usage, _session_usage(live_events))
            return event.data.content, usage
        finally:
            await session.disconnect()


@agent_blueprint.route("/api/agent", methods=["GET"])
def agent_status():
    if error := _access_error():
        return error
    key, conversation = _conversation()
    path = _mcp_path()
    configured = path is not None and path.is_file()
    try:
        auth = asyncio.run(_auth_status(conversation.token))
    except (ImportError, OSError, RuntimeError, ValueError):
        auth = {"authenticated": False, "login": None}
    return _response({**auth, "configured": configured,
                      "token_connected": conversation.token is not None,
                      "messages": conversation.messages,
                      "model": conversation.model, "usage": conversation.usage}, key)


@agent_blueprint.route("/api/agent/auth", methods=["POST", "DELETE"])
def agent_auth():
    if error := _access_error():
        return error
    key, conversation = _conversation()
    if request.method == "DELETE":
        with conversation.lock:
            if conversation.session_id:
                try:
                    asyncio.run(_delete_session(conversation.token, conversation.session_id))
                except Exception:
                    current_app.logger.exception("Could not delete agent session")
                    return _response({"error": "Could not delete the stored conversation."}, key, 503)
            conversation.token = None
            conversation.session_id = None
            conversation.messages.clear()
            conversation.model = "auto"
            conversation.usage = {"cost": None, "input_tokens": None, "output_tokens": None}
        return _response({"authenticated": False}, key)
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return _response({"error": "Expected a JSON object."}, key, 400)
    token = data.get("token")
    if not isinstance(token, str) or not token.startswith(("github_pat_", "gho_", "ghu_")) or len(token) > 512:
        return _response({"error": "Enter a GitHub user token with Copilot access."}, key, 400)
    try:
        auth = asyncio.run(_auth_status(token))
    except (ImportError, OSError, RuntimeError, ValueError):
        return _response({"error": "Could not verify the GitHub token."}, key, 503)
    if not auth["authenticated"]:
        return _response({"error": "GitHub did not accept this token for Copilot."}, key, 401)
    with conversation.lock:
        conversation.token = token
        conversation.session_id = None
        conversation.messages.clear()
        conversation.model = "auto"
        conversation.usage = {"cost": None, "input_tokens": None, "output_tokens": None}
    return _response(auth, key)


@agent_blueprint.route("/api/agent/models", methods=["GET"])
def agent_models():
    if error := _access_error():
        return error
    key, conversation = _conversation()
    try:
        models = asyncio.run(_models(conversation.token))
    except Exception:
        current_app.logger.exception("Could not list agent models")
        return _response({"error": "Unable to load available Copilot models."}, key, 503)
    return _response({"models": models}, key)


@agent_blueprint.route("/api/agent/model", methods=["POST"])
def agent_model():
    if error := _access_error():
        return error
    key, conversation = _conversation()
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("model"), str) or len(data["model"]) > 100:
        return _response({"error": "Invalid model selection."}, key, 400)
    if not conversation.lock.acquire(blocking=False):
        return _response({"error": "The agent is already responding."}, key, 409)
    try:
        try:
            choices = asyncio.run(_models(conversation.token))
        except Exception:
            current_app.logger.exception("Could not verify agent model")
            return _response({"error": "Unable to verify this Copilot model."}, key, 503)
        if data["model"] not in {choice["id"] for choice in choices}:
            return _response({"error": "Selected model is not available for this account."}, key, 400)
        conversation.model = data["model"]
        return _response({"model": conversation.model}, key)
    finally:
        conversation.lock.release()


@agent_blueprint.route("/api/agent/conversation", methods=["DELETE"])
def agent_reset():
    if error := _access_error():
        return error
    key, conversation = _conversation()
    with conversation.lock:
        if conversation.session_id:
            try:
                asyncio.run(_delete_session(conversation.token, conversation.session_id))
            except Exception:
                current_app.logger.exception("Could not delete agent session")
                return _response({"error": "Could not delete the stored conversation."}, key, 503)
        conversation.session_id = None
        conversation.messages.clear()
        conversation.usage = {"cost": None, "input_tokens": None, "output_tokens": None}
    return _response({"messages": [], "usage": conversation.usage}, key)


@agent_blueprint.route("/api/agent/messages", methods=["POST"])
def agent_message():
    if error := _access_error():
        return error
    key, conversation = _conversation()
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return _response({"error": "Expected a JSON object."}, key, 400)
    message = data.get("message")
    if not isinstance(message, str) or not message.strip() or len(message) > 8000:
        return _response({"error": "Enter a message of at most 8000 characters."}, key, 400)
    if not isinstance(data.get("allow_writes", False), bool):
        return _response({"error": "Invalid write permission."}, key, 400)
    model = data.get("model", conversation.model)
    if not isinstance(model, str) or not model or len(model) > 100:
        return _response({"error": "Invalid model selection."}, key, 400)
    try:
        context = _validated_context(data.get("context"))
    except ValueError as exc:
        return _response({"error": str(exc)}, key, 400)
    user_message = message.strip()
    agent_prompt = user_message
    if context:
        agent_prompt = (f"{user_message}\n\nCurrent VulnScout browser view (selection only; verify facts with MCP): "
                        f"{json.dumps(context, separators=(',', ':'))}")
    path = _mcp_path()
    if path is None or not path.is_file():
        return _response({"error": "Set VULNSCOUT_MCP_SERVER_PATH to the vulnscout-mcp run_server.py path."}, key, 503)
    if not conversation.lock.acquire(blocking=False):
        return _response({"error": "The agent is already responding."}, key, 409)
    try:
        try:
            reply, usage = asyncio.run(_reply(conversation, agent_prompt, data.get("allow_writes", False), path, model))
        except UnavailableModelError as exc:
            return _response({"error": str(exc)}, key, 400)
        except Exception:
            current_app.logger.exception("Agent request failed")
            return _response({
                "error": "Agent request failed. Check Copilot sign-in, MCP server, and backend logs.",
            }, key, 503)
        conversation.messages.extend(({"role": "user", "content": user_message},
                                      {"role": "assistant", "content": reply}))
        conversation.model = model
        conversation.usage = usage
        return _response({"reply": reply, "model": model, "usage": usage}, key)
    finally:
        conversation.lock.release()


def init_app(app):
    app.register_blueprint(agent_blueprint)
