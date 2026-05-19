import json
import os
import hashlib
import httpx
import duckdb
from datetime import datetime, timedelta
from anthropic import Anthropic
from http.server import HTTPServer, BaseHTTPRequestHandler

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
client = Anthropic(api_key=ANTHROPIC_API_KEY)
db = duckdb.connect("/app/mcptrust.duckdb")

db.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id VARCHAR PRIMARY KEY,
        server_name VARCHAR,
        score INTEGER,
        grade VARCHAR,
        verdict VARCHAR,
        full_report JSON,
        scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

SYSTEM_PROMPT = """You are an MCP security analyst. Analyze the given MCP server and return ONLY valid JSON:
{
  "name": "server name",
  "score": 0-100,
  "grade": "A/B/C/D/F",
  "verdict": "SAFE/CAUTION/DANGER",
  "summary": "2 sentence summary",
  "checks": {
    "authentication": {"pass": true/false, "detail": "detail"},
    "rateLimit": {"pass": true/false, "detail": "detail"},
    "openSource": {"pass": true/false, "detail": "detail"},
    "recentUpdate": {"pass": true/false, "detail": "detail"},
    "knownCVE": {"pass": true/false, "detail": "detail"},
    "hardcodedSecrets": {"pass": true/false, "detail": "detail"},
    "publisherVerified": {"pass": true/false, "detail": "detail"},
    "dependencySafe": {"pass": true/false, "detail": "detail"}
  },
  "risks": ["risk1", "risk2"],
  "recommendations": ["rec1", "rec2"],
  "category": "DevTools/Database/Communication/Finance/Security/Other",
  "trustTier": "Official/Verified/Community/Unreviewed/Dangerous"
}"""

def analyze(server):
    cache_id = hashlib.md5(server.lower().strip().encode()).hexdigest()
    cached = db.execute(
        "SELECT full_report, scan_time FROM scans WHERE id = ?", [cache_id]
    ).fetchone()
    if cached:
        scan_time = cached[1]
        if isinstance(scan_time, str):
            scan_time = datetime.fromisoformat(scan_time)
        if datetime.now() - scan_time < timedelta(hours=24):
            report = json.loads(cached[0]) if isinstance(cached[0], str) else cached[0]
            report["cached"] = True
            return report

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": f"Analyze this MCP server: {server}"}]
    )
    raw = response.content[0].text.strip()
    clean = raw.replace("```json", "").replace("```", "").strip()
    report = json.loads(clean)
    report["cached"] = False
    report["scanned_at"] = datetime.now().isoformat()

    db.execute("""
        INSERT INTO scans (id, server_name, score, grade, verdict, full_report)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (id) DO UPDATE SET
            score = excluded.score,
            full_report = excluded.full_report,
            scan_time = CURRENT_TIMESTAMP
    """, [cache_id, report.get("name", server),
          report.get("score", 0), report.get("grade", "F"),
          report.get("verdict", "DANGER"), json.dumps(report)])

    return report

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"{datetime.now()} - {format % args}")

    def send_json(self, data, code=200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self.send_json({
                "name": "MCPTrust",
                "status": "online",
                "version": "1.0.0",
                "description": "MCP Server Security Intelligence",
                "endpoints": {
                    "/scan?server=NAME": "Full security scan",
                    "/score?server=NAME": "Quick trust score",
                    "/dangerous": "List dangerous servers",
                    "/stats": "Database statistics"
                }
            })

        elif self.path.startswith("/scan"):
            server = self.path.split("server=")[-1] if "server=" in self.path else ""
            if not server:
                self.send_json({"error": "Missing server parameter"}, 400)
                return
            try:
                result = analyze(server)
                self.send_json(result)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)

        elif self.path.startswith("/score"):
            server = self.path.split("server=")[-1] if "server=" in self.path else ""
            if not server:
                self.send_json({"error": "Missing server parameter"}, 400)
                return
            try:
                result = analyze(server)
                self.send_json({
                    "name": result.get("name"),
                    "score": result.get("score"),
                    "grade": result.get("grade"),
                    "verdict": result.get("verdict"),
                    "cached": result.get("cached", False)
                })
            except Exception as e:
                self.send_json({"error": str(e)}, 500)

        elif self.path == "/dangerous":
            rows = db.execute("""
                SELECT server_name, score, full_report
                FROM scans WHERE verdict = 'DANGER'
                ORDER BY score ASC LIMIT 20
            """).fetchall()
            dangerous = []
            for row in rows:
                report = json.loads(row[2]) if isinstance(row[2], str) else row[2]
                dangerous.append({
                    "name": row[0],
                    "score": row[1],
                    "risks": report.get("risks", [])[:2]
                })
            self.send_json({"total": len(dangerous), "servers": dangerous})

        elif self.path == "/stats":
            stats = db.execute("""
                SELECT COUNT(*),
                    AVG(score),
                    SUM(CASE WHEN verdict='SAFE' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN verdict='DANGER' THEN 1 ELSE 0 END)
                FROM scans
            """).fetchone()
            self.send_json({
                "total_scanned": stats[0] or 0,
                "average_score": round(stats[1] or 0, 1),
                "safe_count": stats[2] or 0,
                "danger_count": stats[3] or 0
            })
        else:
            self.send_json({"error": "Not found"}, 404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    print(f"MCPTrust Server starting on port {port}...")
    print("Endpoints: / /scan /score /dangerous /stats")
    server = HTTPServer(("0.0.0.0", port), Handler)
    server.serve_forever()
