# Agent chat (local MVP)

The **Agent** button opens a chat panel alongside VulnScout. The Flask backend uses the GitHub Copilot SDK to launch [vulnscout-mcp](https://github.com/savoirfairelinux/vulnscout-mcp) over stdio. The agent can read vulnerabilities, assessments, and project context. Assessment and context write tools are available only when **Allow assessment and context changes for the next message** is selected; the selection resets after each message.

This proof of concept is opt-in and **localhost-only**. It is intended for one developer running the backend and frontend on the same machine, not a shared or remotely accessible VulnScout deployment. Do not forward the agent port to other users: the server can access the local user's Copilot identity. The browser never receives the host credentials; a token entered in the panel is kept in server memory until an hour of inactivity and is not persisted in browser storage. Copilot may keep session state in its own local directory.

## Start locally

From the demo worktree, with Python 3.11+ and Node.js installed:

```sh
git clone https://github.com/savoirfairelinux/vulnscout-mcp.git ../vulnscout-mcp
python3 -m venv .venv
.venv/bin/pip install -r requirements/base.txt
export VULNSCOUT_AGENT_ENABLED=1
export VULNSCOUT_MCP_SERVER_PATH="$(realpath ../vulnscout-mcp/run_server.py)"
export FLASK_SQLALCHEMY_DATABASE_URI="sqlite:///$PWD/instance/vulnscout.db"
export FLASK_SCAN_FILE="$(pwd)/instance/agent-demo-status.txt"
mkdir -p instance
printf '__END_OF_SCAN_SCRIPT__\n' > "$FLASK_SCAN_FILE"
.venv/bin/flask --app src.bin.webapp:create_app db upgrade
.venv/bin/flask --app src.bin.webapp:create_app run --host 127.0.0.1 --port 7275
```

The ignored `instance/vulnscout.db` in this worktree is an independent SQLite snapshot of the populated database under the original checkout's `.vulnscout/cache/`. It has been migrated to this branch's schema; running `db upgrade` above affects only the demo copy. Do not point the demo at the original checkout's database. The MCP launcher creates its own virtual environment on first use. In another terminal:

```sh
cd frontend
npm ci
VITE_API_URL=http://127.0.0.1:7275 npm run dev -- --host 127.0.0.1
```

Open the Vite URL and select **Agent** in the navbar. The Vite dev proxy forwards only `/api/agent` to the local Flask server. In production builds the browser uses the same origin as Flask. If the backend is on another port, set `VULNSCOUT_AGENT_API_URL` for both the backend's MCP connection and the Vite dev proxy.

## Connect and chat

The panel detects an existing Copilot CLI or GitHub CLI sign-in on the backend host. Otherwise, use **Connect with token** inside the panel with a fine-grained GitHub user token granted **Copilot Requests** permission. The panel links to GitHub's token creation page; no token goes into a URL or browser storage. A GitHub account with Copilot access (including the free tier) is required. Choose from the models available to that account in the **Model** selector; switching models keeps the current conversation. **Remove connected token** discards the in-memory token and deletes that agent session. **Clear chat** deletes the SDK session and resets its messages and usage while retaining the connection and selected model. Earlier sessions created before using Clear chat may still exist in the local Copilot directory.

Each message includes the active page and project/variant selection, including comparison modes. When a project is shown across all variants, its variant UUIDs are included in the scope; an open vulnerability also contributes its matching variant UUIDs. The vulnerability table sends its filtered, sorted vulnerability IDs (across pagination), search and selected IDs; the Review and Metrics views also share their displayed IDs and open vulnerability. The SBOM table shares filtered package IDs; Scans shares displayed scan IDs, the open result, and scan options; Export shares the wizard step, type, mode, enabled document groups, and selected variants/formats; Settings shares its active tab; AI Context shares its selected project and variant names and IDs. Unsaved form text and API keys are not sent automatically. The vulnerability modal has an Agent button in its header. **Assess open vulnerability** and **Assess all displayed** prepare prompts in the panel; neither turns on write access automatically. For lists over 100 items (50 at project scope), the request sends only the count, and the bulk action asks you to narrow the table. No partial list is silently presented as the full display.

The panel shows cumulative input/output tokens when supplied by the SDK, and sums `assistant.usage.cost` across the current conversation when the SDK supplies a cost value. It does not infer a currency or a token price; when no cost is reported, it says **Cost not reported**.

Read tools are available by default. Enabling writes for a message makes the MCP assessment and context write tools available for that turn, without a second approval prompt. Verify the requested target and scope before enabling writes. This MVP uses request/response chat and in-memory browser conversation state; it does not provide streaming, durable multi-user sessions, or an OAuth app registration flow.