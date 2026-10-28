"""MCP server exposing a codewatch instance to coding agents.

Configure with CODEWATCH_URL and CODEWATCH_TOKEN (a read token is enough unless the agent should start scans).
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("codewatch")

SECURITY_TYPES = "vulnerability,security_hotspot"


def call(path, params=None, body=None):
    base = os.environ.get("CODEWATCH_URL", "http://127.0.0.1:8100").rstrip("/")
    query = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v not in (None, "", False)})
    url = f"{base}/api/{path}" + (f"?{query}" if query else "")
    headers = {"Authorization": f"Bearer {os.environ.get('CODEWATCH_TOKEN', '')}"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        try:
            detail = json.load(exc).get("error")
        except ValueError:
            detail = exc.reason
        raise RuntimeError(f"codewatch API {exc.code}: {detail}") from exc


@mcp.tool()
def list_projects() -> dict:
    """Projects this token can see, with the latest analysis and quality-gate status of each branch."""
    return call("projects/")


@mcp.tool()
def quality_gate(project: str, branch: str = "") -> dict:
    """Latest analysis of a branch (default: main): gate conditions, metrics and per-tool status."""
    return call(f"projects/{project}/status/", {"branch": branch})


@mcp.tool()
def list_issues(
    project: str,
    branch: str = "",
    new_only: bool = False,
    types: str = "",
    severities: str = "",
    tool: str = "",
    path: str = "",
    status: str = "open",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Issues from the latest analysis of a branch, most severe first.

    types: comma list of bug, vulnerability, security_hotspot, code_smell, accessibility.
    severities: comma list of blocker, critical, major, minor, info.
    new_only: only issues in code changed on this branch (vs its merge-base with main).
    path: substring of the repo-relative file path. status: open, resolved or all.
    Each issue has a repo-relative path and line, so it can be fixed in the local working copy.
    """
    return call(f"projects/{project}/issues/", {
        "branch": branch, "new": "1" if new_only else "", "type": types, "severity": severities, "tool": tool,
        "path": path, "status": status, "limit": limit, "offset": offset,
    })


@mcp.tool()
def list_security_hotspots(project: str, branch: str = "", new_only: bool = False, limit: int = 50) -> dict:
    """Vulnerabilities and security hotspots (security-sensitive code to review) from the latest analysis."""
    return list_issues(project, branch, new_only, types=SECURITY_TYPES, limit=limit)


@mcp.tool()
def get_issue(issue_id: int, context_lines: int = 5) -> dict:
    """One issue with the surrounding source lines as analysed (snippet is null if the source wasn't stored)."""
    return call(f"issues/{issue_id}/", {"context": context_lines})


@mcp.tool()
def get_rule(rule_id: str) -> dict:
    """A catalogue rule (e.g. "ruff/F841", or the "rule.id" of an issue): what it checks, why it matters,
    how to fix it with examples (from the tool's documentation and MITRE CWE), and its references."""
    return call(f"rules/{rule_id}/")


@mcp.tool()
def resolve_issue(issue_id: int, status: str, comment: str = "") -> dict:
    """Mark an issue 'false_positive' or 'wont_fix' (with a reason in comment), or 'reopen' it.

    Only for findings that are genuinely not problems; fix real issues in code and rescan instead.
    """
    return call(f"issues/{issue_id}/resolve/", body={"status": status, "comment": comment})


@mcp.tool()
def start_server_scan(project: str, branch: str = "") -> dict:
    """Ask the server to scan a branch from the project's repository URL (needs a scan-scope token).

    Projects without a repository URL are scanned locally with the codewatch-scan CLI instead.
    """
    return call(f"projects/{project}/scan/", body={"branch": branch})


def main():
    mcp.run()


if __name__ == "__main__":
    main()
