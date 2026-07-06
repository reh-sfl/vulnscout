/**
 * NVD CVE Refresh handler — typed fetch wrappers for refresh endpoints.
 */

import { asVulnerability } from "./vulnerabilities";
import type { Vulnerability } from "./vulnerabilities";

export type NvdRefreshSuccess = { kind: "success"; vuln: Vulnerability };
export type NvdRefreshError = {
    kind: "error";
    code: "unavailable";
};
export type NvdRefreshResult = NvdRefreshSuccess | NvdRefreshError;

class NvdRefreshHandler {
    static async triggerSingleRefresh(cveId: string): Promise<NvdRefreshResult> {
        const url = `${import.meta.env.VITE_API_URL}/api/vulnerabilities/${encodeURIComponent(cveId)}/nvd-refresh`;
        const response = await fetch(url, { method: "POST", mode: "cors" });
        if (!response.ok) {
            return { kind: "error", code: "unavailable" };
        }
        const data = await response.json().catch(() => null);
        const vuln = data?.vulnerabilities?.[0];
        if (!vuln) return { kind: "error", code: "unavailable" };
        const parsed = asVulnerability(vuln);
        if (Array.isArray(parsed)) return { kind: "error", code: "unavailable" };
        return { kind: "success", vuln: parsed };
    }
}

export default NvdRefreshHandler;
