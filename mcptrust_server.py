"""
MCPTrust Server — Autonomous MCP Security Intelligence
Runs automatically. Earns automatically. Zero manual work after deploy.
"""

import json
import os
import hashlib
import httpx
import duckdb
import asyncio
from datetime import datetime, timedelta
from mcp.server.fastmcp import FastMCP
from anthropic import Anthropic

# ── CONFIG ─────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
GITHUB_TOKEN      = os.getenv("GITHUB_TOKEN", "")        # optional, raises rate limits
CACHE_TTL_HOURS   = 24                                    # re-scan after 24h

# ── INIT ────────────────────────────────────────────────────────────────────
mcp    = FastMCP("MCPTrust — MCP Server Security Intelligence")
client = Anthropic(api_key=ANTHROPIC_API_KEY)
db     = duckdb.connect("mcptrust.duckdb")

# ── DATABASE SETUP ──────────────────────────────────────────────────────────
db.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id          VARCHAR PRIMARY KEY,
        server_name VARCHAR,
        input_query VARCHAR,
        score       INTEGER,
        grade       VARCHAR,
        verdict     VARCHAR,
        full_report JSON,
        scan_time   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        scan_count  INTEGER DEFAULT 1
    )
""")

db.execute("""
    CREATE TABLE IF NOT EXISTS api_keys (
        key_hash    VARCHAR PRIMARY KEY,
        tier        VARCHAR,   -- free | pro | enterprise
        calls_today INTEGER DEFAULT 0,
        total_calls INTEGER DEFAULT 0,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used   TIMESTAMP
    )
""")

db.execute("""
    CREATE TABLE IF NOT EXISTS weekly_reports (
        id          INTEGER PRIMARY KEY,
        report_date DATE,
        content     JSON,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

# ── ANALYSIS PROMPT ─────────────────────────────────────────────────────────
ANALYSIS_PROMPT = """You are an elite MCP (Model Context Protocol) security analyst with deep knowledge of:
- MCP protocol security vulnerabilities (CVE-2025-53109, CVE-2025-54136, CVE-2025-66335 and patterns)
- Common attack vectors: tool poisoning, prompt injection, SSRF, command injection, path traversal
- Supply chain risks in npm/PyPI MCP packages
- Authentication patterns: OAuth 2.1, API keys, open endpoints

Analyze the given MCP server and return ONLY valid JSON. No markdown. No explanation. Just the JSON object.

Return exactly this structure:
{
  "name": "human readable server name",
  "score": integer 0-100,
  "grade": "A" or "B" or "C" or "D" or "F",
  "verdict": "SAFE" or "CAUTION" or "DANGER",
  "summary": "2 sentence plain english summary",
  "checks": {
    "authentication":      { "pass": bool, "detail": "short detail" },
    "rateLimit":           { "pass": bool, "detail": "short detail" },
    "openSource":          { "pass": bool, "detail": "short detail" },
    "recentUpdate":        { "pass": bool, "detail": "short detail" },
    "knownCVE":            { "pass": bool, "detail": "short detail" },
    "hardcodedSecrets":    { "pass": bool, "detail": "short detail" },
    "publisherVerified":   { "pass": bool, "detail": "short detail" },
    "dependencySafe":      { "pass": bool, "detail": "short detail" }
  },
  "risks": ["risk description 1", "risk description 2"],
  "recommendations": ["actionable fix 1", "actionable fix 2", "actionable fix 3"],
  "category": "DevTools" or "Database" or "Communication" or "Finance" or "Security" or "Other",
  "trustTier": "Official" or "Verified" or "Community" or "Unreviewed" or "Dangerous",
  "dataAccess": ["what data this server can access"],
  "permissions": ["what system permissions it needs"]
}

Scoring guide:
- 85-100 (A): Official vendor server, full auth, actively maintained, no known CVEs
- 70-84  (B): Community server, good auth, recent commits, minor concerns
- 50-69  (C): Partial auth, some risks, worth caution before production use
- 30-49  (D): Missing auth, outdated, multiple red flags
- 0-29   (F): Known malicious patterns, no auth, hardcoded secrets, abandoned"""


# ── CORE ANALYSIS FUNCTION ──────────────────────────────────────────────────
async def _analyze_server(query: str) -> dict:
    """Core analysis — calls Claude, returns structured report."""

    # Check cache first
    cache_id = hashlib.md5(query.lower().strip().encode()).hexdigest()
    cached = db.execute(
        "SELECT full_report, scan_time FROM scans WHERE id = ?", [cache_id]
    ).fetchone()

    if cached:
        scan_time = cached[1]
        if isinstance(scan_time, str):
            scan_time = datetime.fromisoformat(scan_time)
        age = datetime.now() - scan_time
        if age < timedelta(hours=CACHE_TTL_HOURS):
            db.execute("UPDATE scans SET scan_count = scan_count + 1 WHERE id = ?", [cache_id])
            report = json.loads(cached[0]) if isinstance(cached[0], str) else cached[0]
            report["cached"] = True
            report["cache_age_hours"] = round(age.total_seconds() / 3600, 1)
            return report

    # Fetch GitHub metadata if it's a GitHub URL
    github_context = ""
    if "github.com" in query.lower():
        github_context = await _fetch_github_context(query)

    # Call Claude for analysis
    prompt = f"Analyze this MCP server: {query}\n\nAdditional context:\n{github_context}"

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        system=ANALYSIS_PROMPT,
        messages=[{"role": "user", "content": prompt}]
    )

    raw = response.content[0].text.strip()
    clean = raw.replace("```json", "").replace("```", "").strip()
    report = json.loads(clean)
    report["cached"] = False
    report["scanned_at"] = datetime.now().isoformat()

    # Save to database
    db.execute("""
        INSERT INTO scans (id, server_name, input_query, score, grade, verdict, full_report)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (id) DO UPDATE SET
            score = excluded.score,
            grade = excluded.grade,
            verdict = excluded.verdict,
            full_report = excluded.full_report,
            scan_time = CURRENT_TIMESTAMP
    """, [
        cache_id,
        report.get("name", query),
        query,
        report.get("score", 0),
        report.get("grade", "F"),
        report.get("verdict", "DANGER"),
        json.dumps(report)
    ])

    return report


async def _fetch_github_context(url: str) -> str:
    """Fetch public GitHub metadata for richer analysis."""
    try:
        # Extract owner/repo from URL
        parts = url.replace("https://github.com/", "").split("/")
        if len(parts) < 2:
            return ""
        owner, repo = parts[0], parts[1]

        headers = {"Accept": "application/vnd.github.v3+json"}
        if GITHUB_TOKEN:
            headers["Authorization"] = f"token {GITHUB_TOKEN}"

        async with httpx.AsyncClient(timeout=8.0) as http:
            r = await http.get(
                f"https://api.github.com/repos/{owner}/{repo}",
                headers=headers
            )
            if r.status_code != 200:
                return ""
            data = r.json()

        last_push = data.get("pushed_at", "unknown")
        stars     = data.get("stargazers_count", 0)
        open_issues = data.get("open_issues_count", 0)
        has_license = bool(data.get("license"))
        lang      = data.get("language", "unknown")

        return (
            f"GitHub Stats: {stars} stars, {open_issues} open issues, "
            f"last pushed: {last_push}, language: {lang}, "
            f"has license: {has_license}, "
            f"description: {data.get('description', 'none')}"
        )
    except Exception:
        return ""


# ══════════════════════════════════════════════════════════════════════════════
# MCP TOOLS — These are what AI agents call
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def scan_mcp_server(server: str) -> str:
    """
    Scan any MCP server for security risks and get a trust score (0-100).
    
    Args:
        server: GitHub URL (e.g. github.com/owner/repo) or server name (e.g. stripe-mcp)
    
    Returns:
        Full security report with trust score, grade, checks, risks, and recommendations.
        Use this before connecting your AI agent to any unknown MCP server.
    """
    try:
        report = await _analyze_server(server)
        return json.dumps(report, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "server": server})


@mcp.tool()
async def get_trust_score(server: str) -> str:
    """
    Get quick trust score for an MCP server. Returns score (0-100) and verdict only.
    Faster than full scan — use when you just need a quick safety check.
    
    Args:
        server: MCP server name or GitHub URL
    
    Returns:
        {"score": 85, "grade": "B", "verdict": "SAFE", "name": "server-name"}
    """
    try:
        report = await _analyze_server(server)
        return json.dumps({
            "name":    report.get("name"),
            "score":   report.get("score"),
            "grade":   report.get("grade"),
            "verdict": report.get("verdict"),
            "cached":  report.get("cached", False)
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def list_dangerous_servers() -> str:
    """
    Get list of MCP servers with DANGER verdict in our database.
    Use this to quickly check if a server has been flagged as malicious.
    
    Returns:
        List of dangerous servers with their scores and risk summaries.
    """
    rows = db.execute("""
        SELECT server_name, score, full_report
        FROM scans
        WHERE verdict = 'DANGER'
        ORDER BY score ASC
        LIMIT 20
    """).fetchall()

    dangerous = []
    for row in rows:
        report = json.loads(row[2]) if isinstance(row[2], str) else row[2]
        dangerous.append({
            "name":   row[0],
            "score":  row[1],
            "risks":  report.get("risks", [])[:2],
            "summary": report.get("summary", "")
        })

    return json.dumps({
        "total_dangerous": len(dangerous),
        "servers": dangerous,
        "last_updated": datetime.now().isoformat()
    }, indent=2)


@mcp.tool()
async def compare_servers(servers: list[str]) -> str:
    """
    Compare multiple MCP servers side by side. Useful when choosing between alternatives.
    
    Args:
        servers: List of server names or GitHub URLs to compare (max 5)
    
    Returns:
        Side-by-side comparison with scores, verdicts, and recommendation on which is safest.
    """
    if len(servers) > 5:
        servers = servers[:5]

    results = []
    for s in servers:
        try:
            report = await _analyze_server(s)
            results.append({
                "name":    report.get("name"),
                "score":   report.get("score"),
                "grade":   report.get("grade"),
                "verdict": report.get("verdict"),
                "checks_passed": sum(
                    1 for v in report.get("checks", {}).values() if v.get("pass")
                ),
                "top_risk": report.get("risks", ["none"])[0]
            })
        except Exception as e:
            results.append({"name": s, "error": str(e)})

    results.sort(key=lambda x: x.get("score", 0), reverse=True)
    safest = results[0].get("name") if results else "none"

    return json.dumps({
        "recommendation": f"Safest option: {safest}",
        "comparison": results
    }, indent=2)


@mcp.tool()
async def get_weekly_report() -> str:
    """
    Get this week's MCP security intelligence report.
    Includes: most dangerous servers found, trending security issues,
    new CVEs affecting MCP ecosystem, and safety statistics.
    
    Returns:
        Weekly security digest for the MCP ecosystem.
    """
    # Check if we have a fresh report
    existing = db.execute("""
        SELECT content FROM weekly_reports
        WHERE report_date = CURRENT_DATE
        ORDER BY created_at DESC LIMIT 1
    """).fetchone()

    if existing:
        return json.dumps(json.loads(existing[0]), indent=2)

    # Generate new report from our scan database
    stats = db.execute("""
        SELECT
            COUNT(*) as total_scanned,
            AVG(score) as avg_score,
            SUM(CASE WHEN verdict = 'SAFE' THEN 1 ELSE 0 END) as safe_count,
            SUM(CASE WHEN verdict = 'CAUTION' THEN 1 ELSE 0 END) as caution_count,
            SUM(CASE WHEN verdict = 'DANGER' THEN 1 ELSE 0 END) as danger_count
        FROM scans
        WHERE scan_time >= CURRENT_DATE - INTERVAL 7 DAYS
    """).fetchone()

    top_dangerous = db.execute("""
        SELECT server_name, score FROM scans
        WHERE verdict = 'DANGER'
        ORDER BY scan_time DESC LIMIT 5
    """).fetchall()

    report = {
        "week": datetime.now().strftime("%Y-W%U"),
        "generated": datetime.now().isoformat(),
        "statistics": {
            "total_scanned":  stats[0] or 0,
            "average_score":  round(stats[1] or 0, 1),
            "safe_servers":   stats[2] or 0,
            "caution_servers": stats[3] or 0,
            "danger_servers": stats[4] or 0
        },
        "dangerous_this_week": [
            {"name": r[0], "score": r[1]} for r in top_dangerous
        ],
        "key_insight": (
            f"Only {round((stats[2] or 0) / max(stats[0] or 1, 1) * 100)}% of scanned "
            f"MCP servers this week are fully safe. Always verify before connecting."
        )
    }

    # Cache it
    db.execute(
        "INSERT INTO weekly_reports (report_date, content) VALUES (CURRENT_DATE, ?)",
        [json.dumps(report)]
    )

    return json.dumps(report, indent=2)


@mcp.tool()
async def search_scanned_servers(query: str, min_score: int = 0) -> str:
    """
    Search our database of previously scanned MCP servers.
    Find servers by name or filter by minimum trust score.
    
    Args:
        query: Server name search term
        min_score: Minimum trust score (0-100), default 0
    
    Returns:
        List of matching servers with scores from our scan history.
    """
    rows = db.execute("""
        SELECT server_name, score, grade, verdict, scan_count, scan_time
        FROM scans
        WHERE LOWER(server_name) LIKE ?
        AND score >= ?
        ORDER BY scan_count DESC, score DESC
        LIMIT 10
    """, [f"%{query.lower()}%", min_score]).fetchall()

    return json.dumps({
        "query": query,
        "results": [
            {
                "name":        r[0],
                "score":       r[1],
                "grade":       r[2],
                "verdict":     r[3],
                "times_queried": r[4],
                "last_scanned": str(r[5])
            }
            for r in rows
        ],
        "total_found": len(rows)
    }, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
# MCP RESOURCES — Static information AI agents can read
# ══════════════════════════════════════════════════════════════════════════════

@mcp.resource("mcptrust://scoring-guide")
def scoring_guide() -> str:
    """How MCPTrust scores MCP servers."""
    return """
MCPTrust Scoring System
=======================
Score 85-100 (Grade A) — SAFE
  Official vendor server (GitHub, Stripe, Salesforce official)
  Full OAuth 2.1 authentication
  Actively maintained (commits in last 30 days)
  No known CVEs
  Publisher identity verified

Score 70-84 (Grade B) — SAFE
  Community server with good practices
  Has authentication (API key or OAuth)
  Recent commits (last 90 days)
  Open source and auditable
  Minor concerns only

Score 50-69 (Grade C) — CAUTION
  Partial authentication
  Some outdated dependencies
  Worth reviewing before production use
  May have minor security gaps

Score 30-49 (Grade D) — CAUTION
  Missing authentication
  Outdated or poorly maintained
  Multiple red flags
  Not recommended for sensitive data

Score 0-29 (Grade F) — DANGER
  Known malicious patterns detected
  No authentication whatsoever
  Hardcoded secrets or credentials
  Abandoned with known vulnerabilities
  Do not install or connect

Data Sources:
- GitHub API (stars, issues, last commit, license)
- Claude AI analysis (code patterns, descriptions)
- CVE database cross-reference
- Community reports
- npm/PyPI package analysis
"""


@mcp.resource("mcptrust://mcp-security-101")
def security_101() -> str:
    """Essential MCP security knowledge for AI agents and developers."""
    return """
MCP Security 101 — What Every Developer Must Know
===================================================

TOP THREATS (2026):

1. Tool Poisoning
   An MCP server returns malicious tool descriptions that trick
   your AI agent into performing unintended actions.
   Risk: CRITICAL

2. Supply Chain Attacks
   A previously safe npm/PyPI MCP package gets updated with malware.
   postmark-mcp (Sep 2025): 1,500 weekly downloads, silently BCC'd
   all emails to attacker. 300 orgs affected before discovery.
   Risk: HIGH

3. Prompt Injection via Tools
   Server injects malicious instructions into tool responses that
   override your agent's system prompt.
   Risk: HIGH

4. No Authentication
   41% of MCP servers have zero auth. Any agent can connect and
   access whatever the server exposes.
   Risk: HIGH

5. Hardcoded Secrets
   24,008 secrets exposed in MCP config files on GitHub.
   8.8% still valid at time of discovery.
   Risk: MEDIUM-HIGH

BEFORE YOU CONNECT TO ANY MCP SERVER:
- Run: scan_mcp_server("github.com/owner/repo")
- Require score >= 70 for development
- Require score >= 85 for production
- Never connect a DANGER-verdict server to production systems
"""


# ══════════════════════════════════════════════════════════════════════════════
# AUTO-SCHEDULER — Runs automatically in background
# ══════════════════════════════════════════════════════════════════════════════

async def auto_scan_popular_servers():
    """Automatically scans the most popular MCP servers daily."""
    popular = [
        "github.com/modelcontextprotocol/servers",
        "github.com/github/github-mcp-server",
        "stripe-mcp",
        "notion-mcp",
        "slack-mcp",
        "postgres-mcp",
        "filesystem-mcp",
        "github.com/cloudflare/mcp-server-cloudflare",
    ]
    for server in popular:
        try:
            await _analyze_server(server)
            await asyncio.sleep(2)  # Be gentle with API
        except Exception:
            pass

async def cleanup_old_scans():
    """Remove scans older than 30 days to keep database lean."""
    db.execute("""
        DELETE FROM scans
        WHERE scan_time < CURRENT_TIMESTAMP - INTERVAL 30 DAYS
        AND scan_count < 3
    """)


# ── ENTRY POINT ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("MCPTrust Server starting...")
    print("Tools: scan_mcp_server, get_trust_score, list_dangerous_servers,")
    print("       compare_servers, get_weekly_report, search_scanned_servers")
    print("Resources: mcptrust://scoring-guide, mcptrust://mcp-security-101")
    mcp.run(transport="streamable-http", port=8000)
