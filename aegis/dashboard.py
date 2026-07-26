"""Lightweight inspection dashboard for local audit logs."""

from __future__ import annotations

import html
import sqlite3
from collections import Counter
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterable, Optional
from urllib.parse import parse_qs, urlparse

from aegis.db import DB_FILE


@dataclass(frozen=True)
class AuditLogRow:
    event_id: str
    agent_id: str
    tool_name: str
    payload: str
    verdict: str
    triggered_rule: Optional[str]
    latency_ms: float


@dataclass(frozen=True)
class DashboardMetrics:
    total_invocations: int
    allowed_count: int
    blocked_count: int
    top_rules_triggered: list[tuple[str, int]]


def _connect(db_path: str) -> sqlite3.Connection:
    return sqlite3.connect(db_path)


def fetch_audit_rows(
    db_path: str = DB_FILE,
    verdict: Optional[str] = None,
    agent_id: Optional[str] = None,
    limit: int = 50,
) -> list[AuditLogRow]:
    query = [
        "SELECT id, agent_id, tool_name, payload, verdict, triggered_rule, latency_ms",
        "FROM audit_logs",
    ]
    conditions: list[str] = []
    parameters: list[Any] = []

    if verdict:
        conditions.append("verdict = ?")
        parameters.append(verdict)
    if agent_id:
        conditions.append("agent_id = ?")
        parameters.append(agent_id)

    if conditions:
        query.append("WHERE " + " AND ".join(conditions))

    query.append("ORDER BY created_at DESC, rowid DESC")
    query.append("LIMIT ?")
    parameters.append(limit)

    with _connect(db_path) as connection:
        cursor = connection.cursor()
        cursor.execute(" ".join(query), parameters)
        rows = cursor.fetchall()

    return [
        AuditLogRow(
            event_id=row[0],
            agent_id=row[1],
            tool_name=row[2],
            payload=row[3],
            verdict=row[4],
            triggered_rule=row[5],
            latency_ms=float(row[6]),
        )
        for row in rows
    ]


def calculate_dashboard_metrics(db_path: str = DB_FILE) -> DashboardMetrics:
    with _connect(db_path) as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT verdict, triggered_rule FROM audit_logs")
        rows = cursor.fetchall()

    total_invocations = len(rows)
    allowed_count = sum(1 for verdict, _ in rows if verdict == "ALLOW")
    blocked_count = sum(1 for verdict, _ in rows if verdict == "BLOCK")
    rule_counter = Counter(rule for _, rule in rows if rule)

    return DashboardMetrics(
        total_invocations=total_invocations,
        allowed_count=allowed_count,
        blocked_count=blocked_count,
        top_rules_triggered=rule_counter.most_common(5),
    )


def _status_class(verdict: str) -> str:
    if verdict == "ALLOW":
        return "status-allow"
    if verdict == "BLOCK":
        return "status-block"
    return "status-warning"


def _render_rows(rows: Iterable[AuditLogRow]) -> str:
    rendered = []
    for row in rows:
        rendered.append(
            "<tr>"
            f"<td>{html.escape(row.event_id)}</td>"
            f"<td>{html.escape(row.agent_id)}</td>"
            f"<td>{html.escape(row.tool_name)}</td>"
            f"<td><span class='badge {_status_class(row.verdict)}'>{html.escape(row.verdict)}</span></td>"
            f"<td>{html.escape(row.triggered_rule or '-')}</td>"
            f"<td class='mono'>{html.escape(row.payload)}</td>"
            f"<td>{row.latency_ms:.3f} ms</td>"
            "</tr>"
        )
    return "".join(rendered) or "<tr><td colspan='7'>No audit logs found</td></tr>"


def render_dashboard_html(
    metrics: DashboardMetrics,
    rows: list[AuditLogRow],
    verdict: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> str:
    top_rules_html = "".join(
        f"<li><span>{html.escape(rule)}</span><strong>{count}</strong></li>" for rule, count in metrics.top_rules_triggered
    ) or "<li><span>No triggered rules yet</span><strong>0</strong></li>"
    rows_html = _render_rows(rows)
    verdict_label = html.escape(verdict or "All")
    agent_label = html.escape(agent_id or "All")

    return f"""<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>Aegis Dashboard</title>
  <style>
    :root {{
      --bg-primary: #09090b;
      --bg-secondary: #18181b;
      --border-color: #27272a;
      --text-primary: #f4f4f5;
      --text-muted: #a1a1aa;
      --accent-emerald: #10b981;
      --accent-rose: #f43f5e;
      --accent-amber: #f59e0b;
      --accent-cyan: #06b6d4;
      --sidebar-width: 240px;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Inter, -apple-system, sans-serif; background: var(--bg-primary); color: var(--text-primary); }}
    .shell {{ display: grid; grid-template-columns: var(--sidebar-width) 1fr; min-height: 100vh; }}
    .sidebar {{ background: linear-gradient(180deg, #111113, #09090b); border-right: 1px solid var(--border-color); padding: 24px 18px; }}
    .brand {{ font-size: 20px; font-weight: 700; letter-spacing: 0.02em; margin-bottom: 24px; }}
    .nav {{ display: grid; gap: 10px; }}
    .nav a {{ color: var(--text-muted); text-decoration: none; padding: 10px 12px; border-radius: 10px; background: transparent; }}
    .nav a.active, .nav a:hover {{ color: var(--text-primary); background: var(--bg-secondary); }}
    .main {{ padding: 20px; }}
    .header {{ display: flex; justify-content: space-between; align-items: center; gap: 16px; margin-bottom: 20px; }}
    .header .meta {{ color: var(--text-muted); font-size: 14px; display: flex; gap: 14px; flex-wrap: wrap; }}
    .status-dot {{ width: 10px; height: 10px; border-radius: 999px; background: var(--accent-emerald); display: inline-block; margin-right: 8px; }}
    .grid {{ display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 16px; }}
    .card {{ background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 18px; padding: 18px; }}
    .span-3 {{ grid-column: span 3; }}
    .span-4 {{ grid-column: span 4; }}
    .span-6 {{ grid-column: span 6; }}
    .span-12 {{ grid-column: span 12; }}
    .kpi {{ font-size: 30px; font-weight: 700; margin: 10px 0 0; }}
    .muted {{ color: var(--text-muted); }}
    .controls {{ display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; }}
    .pill {{ border: 1px solid var(--border-color); background: #111113; color: var(--text-primary); border-radius: 999px; padding: 8px 12px; text-decoration: none; }}
    .badge {{ padding: 5px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; }}
    .status-allow {{ background: rgba(16,185,129,0.15); color: var(--accent-emerald); }}
    .status-block {{ background: rgba(244,63,94,0.15); color: var(--accent-rose); }}
    .status-warning {{ background: rgba(245,158,11,0.15); color: var(--accent-amber); }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ border-bottom: 1px solid var(--border-color); text-align: left; padding: 12px 10px; vertical-align: top; }}
    th {{ color: var(--text-muted); font-weight: 600; }}
    .mono {{ font-family: "JetBrains Mono", "Fira Code", monospace; white-space: pre-wrap; word-break: break-word; }}
    .rule-list {{ list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; }}
    .rule-list li {{ display: flex; justify-content: space-between; gap: 16px; padding: 10px 12px; background: #111113; border-radius: 12px; border: 1px solid var(--border-color); }}
    @media (max-width: 960px) {{
      .shell {{ grid-template-columns: 1fr; }}
      .sidebar {{ border-right: none; border-bottom: 1px solid var(--border-color); }}
      .span-3, .span-4, .span-6 {{ grid-column: span 12; }}
    }}
  </style>
</head>
<body>
  <div class='shell'>
    <aside class='sidebar'>
      <div class='brand'>Aegis</div>
      <nav class='nav'>
        <a class='active' href='/'>Dashboard</a>
        <a href='/'>Live Interceptions</a>
        <a href='/'>Audit Logs</a>
        <a href='/'>Policy Management</a>
      </nav>
    </aside>
    <main class='main'>
      <div class='header'>
        <div>
          <h1 style='margin:0 0 6px;'>Inspection Dashboard</h1>
          <div class='meta'><span><span class='status-dot'></span>System Online</span><span>Environment: Development</span><span>Verdict: {verdict_label}</span><span>Agent: {agent_label}</span></div>
        </div>
        <div class='meta'><span>Realtime audit visibility</span></div>
      </div>

      <section class='grid'>
        <div class='card span-3'><div class='muted'>Total Invocations</div><div class='kpi'>{metrics.total_invocations}</div></div>
        <div class='card span-3'><div class='muted'>Allowed</div><div class='kpi' style='color: var(--accent-emerald);'>{metrics.allowed_count}</div></div>
        <div class='card span-3'><div class='muted'>Blocked</div><div class='kpi' style='color: var(--accent-rose);'>{metrics.blocked_count}</div></div>
        <div class='card span-3'><div class='muted'>Top Rule</div><div class='kpi' style='color: var(--accent-cyan);'>{html.escape(metrics.top_rules_triggered[0][0]) if metrics.top_rules_triggered else 'None'}</div></div>

        <div class='card span-4'>
          <h2 style='margin-top:0;'>Top Rules Triggered</h2>
          <ul class='rule-list'>{top_rules_html}</ul>
        </div>

        <div class='card span-8'>
          <h2 style='margin-top:0;'>Audit Logs</h2>
          <div class='controls'>
            <a class='pill' href='/'>All</a>
            <a class='pill' href='/?verdict=ALLOW'>ALLOW</a>
            <a class='pill' href='/?verdict=BLOCK'>BLOCK</a>
          </div>
          <div class='controls muted'>Filtering by verdict and agent ID is supported via query parameters.</div>
          <div style='overflow:auto;'>
            <table>
              <thead>
                <tr>
                  <th>Event</th><th>Agent</th><th>Tool</th><th>Status</th><th>Rule</th><th>Payload</th><th>Latency</th>
                </tr>
              </thead>
              <tbody>{rows_html}</tbody>
            </table>
          </div>
        </div>
      </section>
    </main>
  </div>
</body>
</html>"""


class DashboardRequestHandler(BaseHTTPRequestHandler):
    db_path: str = DB_FILE

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path not in {"/", "/index.html"}:
            self.send_error(404, "Not Found")
            return

        params = parse_qs(parsed.query)
        verdict = params.get("verdict", [None])[0]
        agent_id = params.get("agent_id", [None])[0]

        try:
            metrics = calculate_dashboard_metrics(self.db_path)
            rows = fetch_audit_rows(self.db_path, verdict=verdict, agent_id=agent_id)
            content = render_dashboard_html(metrics, rows, verdict=verdict, agent_id=agent_id).encode("utf-8")
        except sqlite3.Error as exc:
            content = f"<html><body><h1>Dashboard Error</h1><pre>{html.escape(str(exc))}</pre></body></html>".encode("utf-8")
            self.send_response(500)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


def create_dashboard_server(host: str = "127.0.0.1", port: int = 8000, db_path: str = DB_FILE) -> ThreadingHTTPServer:
    handler = type("AegisDashboardHandler", (DashboardRequestHandler,), {"db_path": db_path})
    return ThreadingHTTPServer((host, port), handler)


def run_dashboard(host: str = "127.0.0.1", port: int = 8000, db_path: str = DB_FILE) -> ThreadingHTTPServer:
    server = create_dashboard_server(host=host, port=port, db_path=db_path)
    print(f"Aegis dashboard running at http://{host}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return server