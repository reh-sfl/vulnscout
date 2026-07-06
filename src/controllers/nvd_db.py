# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Backward-compatible shim — NVD CVE JSON extraction helpers.

The NVD REST API integration has been removed. CVE data is now sourced
from the local NVD-FKIE git feed managed by sbom-cve-check (see
:func:`~src.controllers.scc_engine.get_cve_json`).

This module re-exports the pure extraction functions from
:mod:`~src.controllers.nvd_extract` under the original ``NVD_DB`` class
name so that existing call sites that use ``NVD_DB.extract_cve_details``
continue to work without modification.
"""

from .nvd_extract import extract_cve_details, api_weaknesses_to_list_str, api_references_filter_patches


class NVD_DB:
    """Backward-compat shim — use :mod:`nvd_extract` module functions directly."""

    extract_cve_details = staticmethod(extract_cve_details)
    api_weaknesses_to_list_str = staticmethod(api_weaknesses_to_list_str)
    api_references_filter_patches = staticmethod(api_references_filter_patches)
