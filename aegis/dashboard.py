"""Local multi-view dashboard for Aegis audit telemetry."""

from __future__ import annotations

import html
import json
import os
import re
import sqlite3
import time
from collections import Counter
from contextlib import closing
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence
from urllib.parse import parse_qs, urlparse

DB_FILE = os.getenv("AEGIS_DB_PATH", "aegis_audit.db")
POLICY_FILE = Path("guardrails.yaml")
DEFAULT_LIMIT = 2000
STREAM_POLL_SECONDS = 1.0
MAX_VIRTUAL_ROWS = 5000


@dataclass(frozen=True)
class AuditLogRow:
    """Single audit row from the local SQLite telemetry database."""

    rowid: int
    created_at: str
    agent_id: str
    tool_name: str
    payload: str
    verdict: str
    triggered_rule: Optional[str]
    latency_ms: float


@dataclass(frozen=True)
class DashboardMetrics:
    """Summary metrics rendered in the dashboard header and live view."""

    total_calls: int = 0
    allowed_calls: int = 0
    blocked_calls: int = 0
    warning_calls: int = 0
    unique_agents: int = 0
    unique_tools: int = 0
    top_rules: list[tuple[str, int]] = field(default_factory=list)
    top_tools: list[tuple[str, int]] = field(default_factory=list)


@dataclass(frozen=True)
class ToolRegistryEntry:
    """Aggregated tool-sprawl telemetry for the registry view."""

    tool_name: str
    calls: int
    allowed: int
    blocked: int
    last_seen: str


@dataclass(frozen=True)
class PolicyPreview:
    """Local policy file preview for the configurator view."""

    exists: bool
    path: str
    content: str
    rules: list[str]


@dataclass(frozen=True)
class DashboardSnapshot:
    """Complete data payload used by the client-side application shell."""

    metrics: DashboardMetrics
    logs: list[AuditLogRow]
    registry: list[ToolRegistryEntry]
    policy: PolicyPreview

    def as_json(self) -> dict[str, Any]:
        return {
            "metrics": asdict(self.metrics),
            "logs": [_serialize_row(row) for row in self.logs],
            "registry": [asdict(entry) for entry in self.registry],
            "policy": asdict(self.policy),
        }


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Aegis Security Operations</title>
  <style>
    :root {
      --bg-main: #090d16;
      --bg-surface: #111827;
      --border-color: #1f2937;
      --text-main: #f9fafb;
      --text-muted: #9ca3af;
      --primary: #3b82f6;
      --allow: #10b981;
      --block: #ef4444;
      --warning: #f59e0b;
      --sidebar-width: 280px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg-main);
      color: var(--text-main);
      display: flex;
      height: 100vh;
      overflow: hidden;
    }

    aside {
      width: var(--sidebar-width);
      background-color: var(--bg-surface);
      border-right: 1px solid var(--border-color);
      display: flex;
      flex-direction: column;
      padding: 24px;
      gap: 24px;
      flex-shrink: 0;
    }

    .brand-area h1 {
      font-size: 1.25rem;
      font-weight: 700;
      color: var(--text-main);
      margin-top: 4px;
    }

    .nav-buttons {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .nav-btn {
      text-align: left;
      background: transparent;
      border: 1px solid transparent;
      padding: 12px 16px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 0.9rem;
      color: var(--text-muted);
      transition: all 0.2s ease;
    }

    .nav-btn:hover {
      background-color: rgba(255, 255, 255, 0.03);
      color: var(--text-main);
    }

    .nav-btn.active {
      background-color: rgba(59, 130, 246, 0.12);
      color: var(--primary);
      border-color: rgba(59, 130, 246, 0.3);
      font-weight: 600;
    }

    main {
      flex: 1;
      display: flex;
      flex-direction: column;
      overflow-y: auto;
      padding: 32px;
      gap: 24px;
    }

    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 16px;
    }

    header h2 {
      font-size: 1.5rem;
      font-weight: 600;
      color: var(--text-main);
    }

    .filters-bar {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      background: var(--bg-surface);
      padding: 16px;
      border-radius: 12px;
      border: 1px solid var(--border-color);
      align-items: center;
    }

    .filters-bar select, .filters-bar input {
      padding: 8px 12px;
      border-radius: 6px;
      border: 1px solid var(--border-color);
      font-size: 0.85rem;
      background: var(--bg-main);
      color: var(--text-main);
    }

    .filter-chips {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    .chip {
      background: rgba(255, 255, 255, 0.05);
      padding: 4px 10px;
      border-radius: 16px;
      font-size: 0.75rem;
      color: var(--text-muted);
      border: 1px solid var(--border-color);
    }

    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
    }

    .metric-pill {
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      padding: 20px;
      border-radius: 12px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .metric-pill .label {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      font-weight: 600;
    }

    .metric-pill .value {
      font-size: 1.75rem;
      font-weight: 700;
      color: var(--text-main);
    }

    .panel {
      display: none;
      flex-direction: column;
      gap: 16px;
    }

    .panel.is-visible {
      display: flex;
    }

    .explorer-viewport {
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      height: 550px;
      overflow-y: auto;
      position: relative;
    }

    .table-header-row {
      display: grid;
      grid-template-columns: 160px 140px 140px 130px 180px 130px 1fr;
      padding: 14px 16px;
      border-bottom: 1px solid var(--border-color);
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      background: rgba(17, 24, 39, 0.95);
      position: sticky;
      top: 0;
      z-index: 5;
    }

    .table-row {
      display: grid;
      grid-template-columns: 160px 140px 140px 130px 180px 130px 1fr;
      padding: 12px 16px;
      border-bottom: 1px solid var(--border-color);
      font-size: 0.85rem;
      align-items: center;
    }

    .table-row:hover {
      background: rgba(255, 255, 255, 0.02);
    }

    .table-cell {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: var(--text-main);
    }

    .muted { color: var(--text-muted); }

    .verdict-allow { color: var(--allow); font-weight: 600; background: rgba(16, 185, 129, 0.1); padding: 3px 8px; border-radius: 4px; border: 1px solid rgba(16, 185, 129, 0.2); }
    .verdict-block { color: var(--block); font-weight: 600; background: rgba(239, 68, 68, 0.1); padding: 3px 8px; border-radius: 4px; border: 1px solid rgba(239, 68, 68, 0.2); }
    .verdict-warning { color: var(--warning); font-weight: 600; background: rgba(245, 158, 11, 0.1); padding: 3px 8px; border-radius: 4px; border: 1px solid rgba(245, 158, 11, 0.2); }
  </style>
</head>
<body>
  <aside>
    <div class="brand-area" style="display: flex; flex-direction: column; gap: 12px;">
      <div style="display: flex; align-items: center; gap: 10px;">
        <div style="width: 32px; height: 32px; background: linear-gradient(135deg, #3b82f6, #1d4ed8); border-radius: 8px; display: flex; align-items: center; justify-content: center;">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </div>
        <div>
          <h1 style="font-size: 1.15rem; font-weight: 800; color: var(--text-main); margin: 0;">Aegis</h1>
          <span style="font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: var(--primary);">Security Operations</span>
        </div>
      </div>
      <p style="font-size: 0.8rem; color: var(--text-muted); line-height: 1.4;">
        Safeguarding your AI agents in real-time with smart safety rules and live human sign-offs.
      </p>
    </div>

    <div class="nav-buttons">
      <button class="nav-btn active" data-view="live-monitor">Live Activity Stream</button>
      <button class="nav-btn" data-view="policy-panel">Security Guardrails</button>
      <button class="nav-btn" data-view="tool-registry">Connected AI Tools</button>
      <button class="nav-btn" data-view="audit-explorer">Activity History</button>
    </div>

    <div style="margin-top: auto; background: var(--bg-main); border: 1px solid var(--border-color); border-radius: 10px; padding: 12px; display: flex; flex-direction: column; gap: 6px;">
      <div style="display: flex; align-items: center; gap: 8px;">
        <span style="width: 8px; height: 8px; border-radius: 50%; background: var(--allow); display: inline-block;"></span>
        <span style="font-size: 0.8rem; font-weight: 600; color: var(--text-main);">System Operational</span>
      </div>
      <div style="font-size: 0.75rem; color: var(--text-muted);">
        Environment: Production Secure
      </div>
    </div>
  </aside>

  <main>
    <header>
      <div>
        <h2 id="current-view-title">Live Activity Stream</h2>
        <p class="muted" style="font-size: 0.85rem;">Real-time feed of AI actions, security intercepts, and pending approvals.</p>
      </div>
      <div>
        <span id="last-event-label" class="chip">Listening for activity...</span>
      </div>
    </header>

    <!-- Panel 1: Live Monitor -->
    <section class="panel is-visible" data-view-panel="live-monitor">
      <div class="filters-bar" style="margin-bottom: 4px;">
        <select id="filter-verdict">
          <option value="all">Safety Status: All</option>
          <option value="ALLOW">Allowed</option>
          <option value="BLOCK">Blocked</option>
          <option value="REQUIRE_APPROVAL">Needs Review</option>
        </select>
        <input type="text" id="filter-agent" placeholder="Filter by Agent Name...">
        <input type="text" id="filter-rule" placeholder="Filter by Rule Trigger...">
        <input type="text" id="filter-search" placeholder="Search parameters & tools...">
      </div>
      <div id="filter-chips" class="filter-chips"></div>

      <div id="live-metrics" class="metrics-grid"></div>
      <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px;">
        <h3 style="font-size: 1rem; margin-bottom: 12px; color: var(--text-main);">Frequently Triggered Safety Rules</h3>
        <div id="live-top-rules"></div>
      </div>
      <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px;">
        <h3 style="font-size: 1rem; margin-bottom: 12px; color: var(--text-main);">Live Stream Activity</h3>
        <div id="live-feed"></div>
      </div>
    </section>

    <!-- Panel 2: Policy Configurator -->
    <section class="panel" data-view-panel="policy-panel">
      <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 12px; padding: 24px; display: flex; flex-direction: column; gap: 20px;">
        <div>
          <h3 style="font-size: 1.15rem; font-weight: 600; color: var(--text-main); margin-bottom: 4px;">Security Guardrail Manager</h3>
          <p class="muted" style="font-size: 0.85rem;">Active configuration rules protecting your AI agent fleet.</p>
        </div>
        <div>
          <h4 style="font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 10px;">Enforced Safety Rules</h4>
          <div id="policy-rules"></div>
        </div>
        <div>
          <h4 style="font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 10px;">Configuration Source</h4>
          <pre id="policy-preview" style="background: #030712; color: #f8fafc; padding: 18px; border-radius: 8px; border: 1px solid var(--border-color); overflow-x: auto; font-size: 0.8rem; line-height: 1.5; font-family: monospace;"></pre>
        </div>
      </div>
    </section>

    <!-- Panel 3: Tool Registry -->
    <section class="panel" data-view-panel="tool-registry">
      <div style="margin-bottom: 4px;">
        <h3 style="font-size: 1.15rem; font-weight: 600; color: var(--text-main); margin-bottom: 4px;">Connected AI Tools</h3>
        <p class="muted" style="font-size: 0.85rem;">Overview of all capabilities and live tools accessed by your AI agents.</p>
      </div>
      <div id="tool-registry" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px;"></div>
    </section>

    <!-- Panel 4: Audit Explorer -->
    <section class="panel" data-view-panel="audit-explorer">
      <div style="margin-bottom: 4px;">
        <h3 style="font-size: 1.15rem; font-weight: 600; color: var(--text-main); margin-bottom: 4px;">Activity History</h3>
        <p class="muted" style="font-size: 0.85rem;">Comprehensive audit trail of every tool execution and safety check.</p>
      </div>
      <div id="explorer-viewport" class="explorer-viewport">
        <div class="table-header-row">
          <div>Timestamp</div>
          <div>Agent Name</div>
          <div>Tool Used</div>
          <div>Safety Status</div>
          <div>Triggered Rule</div>
          <div>Response Time</div>
          <div>Action Parameters</div>
        </div>
        <div id="explorer-spacer" style="position: relative;">
          <div id="explorer-window" style="position: absolute; left: 0; right: 0; top: 0;"></div>
        </div>
      </div>
      <div id="explorer-footer" class="muted" style="font-size: 0.8rem; padding-left: 4px;"></div>
    </section>
  </main>

  <script>
    const ROW_HEIGHT = 45;
    const OVERSCAN = 10;
    const MAX_VIRTUAL_ROWS = 1000;

    const state = {
      view: 'live-monitor',
      metrics: null,
      logs: [],
      registry: [],
      policy: { exists: false, content: '', rules: [] },
      lastSeenRowId: 0,
      renderQueued: false,
      filters: { verdict: 'all', agent_id: '', rule_name: '', search: '' },
      eventSource: null
    };

    const els = {
      navButtons: document.querySelectorAll('.nav-btn'),
      panels: document.querySelectorAll('.panel'),
      currentViewTitle: document.getElementById('current-view-title'),
      filterVerdict: document.getElementById('filter-verdict'),
      filterAgent: document.getElementById('filter-agent'),
      filterRule: document.getElementById('filter-rule'),
      filterSearch: document.getElementById('filter-search'),
      filterChips: document.getElementById('filter-chips'),
      liveMetrics: document.getElementById('live-metrics'),
      liveTopRules: document.getElementById('live-top-rules'),
      liveFeed: document.getElementById('live-feed'),
      policyRules: document.getElementById('policy-rules'),
      policyPreview: document.getElementById('policy-preview'),
      toolRegistry: document.getElementById('tool-registry'),
      explorerViewport: document.getElementById('explorer-viewport'),
      explorerSpacer: document.getElementById('explorer-spacer'),
      explorerWindow: document.getElementById('explorer-window'),
      explorerFooter: document.getElementById('explorer-footer'),
      lastEventLabel: document.getElementById('last-event-label'),
    };

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function formatNumber(num) {
      return new Intl.NumberFormat().format(num || 0);
    }

    function formatLatency(ms) {
      if (ms === null || ms === undefined) return '—';
      return `${Number(ms).toFixed(2)} ms`;
    }

    function verdictClass(verdict) {
      if (verdict === 'ALLOW') return 'verdict-allow';
      if (verdict === 'BLOCK') return 'verdict-block';
      return 'verdict-warning';
    }

    async function resolveApproval(rowid, action) {
      try {
        const response = await fetch(`/api/approve?rowid=${rowid}&action=${action}`);
        const result = await response.json();
        if (result.success) {
          const target = state.logs.find(r => r.rowid === rowid);
          if (target) {
            target.verdict = result.verdict;
            queueRender();
          }
        }
      } catch (err) {
        console.error("Failed to resolve approval:", err);
      }
    }

    function normalizeRow(row) {
      return {
        rowid: Number(row.rowid || 0),
        created_at: String(row.created_at || ''),
        agent_id: String(row.agent_id || ''),
        tool_name: String(row.tool_name || ''),
        payload: String(row.payload || ''),
        verdict: String(row.verdict || ''),
        triggered_rule: row.triggered_rule ? String(row.triggered_rule) : null,
        latency_ms: Number(row.latency_ms || 0)
      };
    }

    function persistState() {
      try {
        localStorage.setItem('aegis_dashboard_filters', JSON.stringify(state.filters));
        localStorage.setItem('aegis_dashboard_view', state.view);
      } catch (_) {}
    }

    function restoreState() {
      try {
        const savedFilters = localStorage.getItem('aegis_dashboard_filters');
        if (savedFilters) state.filters = JSON.parse(savedFilters);
        const savedView = localStorage.getItem('aegis_dashboard_view');
        if (savedView) state.view = savedView;
        if (location.hash) {
          const hashView = location.hash.replace('#', '');
          if (hashView) state.view = hashView;
        }
      } catch (_) {}
    }

    function dedupeAndSort(rows) {
      const seen = new Set();
      const merged = [];
      for (const rawRow of rows) {
        const row = normalizeRow(rawRow);
        if (!seen.has(row.rowid)) {
          seen.add(row.rowid);
          merged.push(row);
        }
      }
      return merged.sort((a, b) => b.rowid - a.rowid);
    }

    function passesFilters(row) {
      const verdict = state.filters.verdict;
      const agent = state.filters.agent_id.trim().toLowerCase();
      const rule = state.filters.rule_name.trim().toLowerCase();
      const search = state.filters.search.trim().toLowerCase();

      if (verdict !== 'all' && row.verdict !== verdict) return false;
      if (agent && !row.agent_id.toLowerCase().includes(agent)) return false;
      if (rule && !String(row.triggered_rule || '').toLowerCase().includes(rule)) return false;
      if (search) {
        const haystack = `${row.tool_name} ${row.payload} ${row.agent_id} ${row.triggered_rule || ''} ${row.verdict}`.toLowerCase();
        if (!haystack.includes(search)) return false;
      }
      return true;
    }

    function filteredRows() {
      return state.logs.filter(passesFilters);
    }

    function computeMetrics(rows) {
      const total = rows.length;
      const allowed = rows.filter((row) => row.verdict === 'ALLOW').length;
      const blocked = rows.filter((row) => row.verdict === 'BLOCK').length;
      const warnings = Math.max(total - allowed - blocked, 0);
      const uniqueAgents = new Set(rows.map((row) => row.agent_id)).size;
      const uniqueTools = new Set(rows.map((row) => row.tool_name)).size;
      const ruleCounter = new Map();
      rows.forEach((row) => {
        if (row.triggered_rule) {
          ruleCounter.set(row.triggered_rule, (ruleCounter.get(row.triggered_rule) || 0) + 1);
        }
      });
      const topRules = Array.from(ruleCounter.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5);
      return {
        total_calls: total,
        allowed_calls: allowed,
        blocked_calls: blocked,
        warning_calls: warnings,
        unique_agents: uniqueAgents,
        unique_tools: uniqueTools,
        top_rules: topRules,
      };
    }

    function renderFilterChips(rows) {
      const chips = [];
      chips.push(`<span class="chip">Active view: <strong>${escapeHtml(state.view.replace('-', ' '))}</strong></span>`);
      chips.push(`<span class="chip">Filtered records: <strong>${formatNumber(rows.length)}</strong></span>`);
      chips.push(`<span class="chip">Status: <strong>${escapeHtml(state.filters.verdict)}</strong></span>`);
      if (state.filters.agent_id.trim()) chips.push(`<span class="chip">Agent: <strong>${escapeHtml(state.filters.agent_id.trim())}</strong></span>`);
      if (state.filters.rule_name.trim()) chips.push(`<span class="chip">Rule: <strong>${escapeHtml(state.filters.rule_name.trim())}</strong></span>`);
      if (state.filters.search.trim()) chips.push(`<span class="chip">Search: <strong>${escapeHtml(state.filters.search.trim())}</strong></span>`);
      els.filterChips.innerHTML = chips.join('');
    }

    function renderMetrics(rows) {
      const metrics = computeMetrics(rows);
      state.metrics = metrics;
      els.liveMetrics.innerHTML = [
        ["Total Activity", metrics.total_calls, "Total actions attempted by AI agents."],
        ["Approved", metrics.allowed_calls, "Safe actions successfully completed."],
        ["Blocked", metrics.blocked_calls, "Unsafe actions safely intercepted."],
        ["Needs Review", metrics.warning_calls, "Actions paused awaiting human sign-off."],
        ["Active Agents", metrics.unique_agents, "Unique AI assistants currently running."],
        ["Tools Used", metrics.unique_tools, "Different tools accessed."],
      ].map(([label, value, hint]) => `
        <div class="metric-pill">
          <div class="label">${label}</div>
          <div class="value">${formatNumber(value)}</div>
          <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px;">${hint}</div>
        </div>
      `).join('');

      els.liveTopRules.innerHTML = metrics.top_rules.length ? metrics.top_rules.map(([rule, count]) => `
        <div style="display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid var(--border-color); font-size: 0.85rem;">
          <span style="color: var(--primary);"><code>${escapeHtml(rule)}</code></span>
          <span class="muted">${formatNumber(count)} triggers</span>
        </div>
      `).join('') : `<div style="padding: 20px; text-align: center; color: var(--text-muted);">No rules triggered in the current filter scope.</div>`;
    }

    function renderLiveFeed(rows) {
      const feedRows = rows.slice(0, 10);
      if (!feedRows.length) {
        els.liveFeed.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--text-muted);">No activity matches your active filters.</div>';
        return;
      }
      els.liveFeed.innerHTML = feedRows.map((row) => {
        const isPending = row.verdict === 'REQUIRE_APPROVAL' || row.verdict === 'WARNING';
        const badgeClass = verdictClass(row.verdict);
        
        return `
          <div style="background: var(--bg-main); border: 1px solid var(--border-color); border-radius: 10px; padding: 16px; margin-bottom: 12px; display: flex; flex-direction: column; gap: 10px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div style="display: flex; align-items: center; gap: 8px;">
                <span class="${badgeClass}" style="font-size: 0.75rem;">${escapeHtml(row.verdict)}</span>
                <span style="font-size: 0.8rem; font-weight: 600; color: var(--text-muted);">Request #${row.rowid}</span>
              </div>
              <span style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(row.created_at)}</span>
            </div>
            
            <div style="font-size: 0.9rem; color: var(--text-main); line-height: 1.4;">
              AI assistant <strong>"${escapeHtml(row.agent_id)}"</strong> invoked tool <code>${escapeHtml(row.tool_name)}</code>.
            </div>

            <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; padding: 10px; font-family: monospace; font-size: 0.75rem; color: var(--text-main); overflow-x: auto;">
              ${escapeHtml(row.payload)}
            </div>

            <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.75rem; color: var(--text-muted); padding-top: 4px;">
              <span>Response Time: ${formatLatency(row.latency_ms)}</span>
              ${isPending ? `
                <div style="display: flex; gap: 8px;">
                  <button onclick="resolveApproval(${row.rowid}, 'BLOCK')" style="background: var(--bg-surface); color: var(--text-main); border: 1px solid var(--border-color); padding: 6px 14px; border-radius: 6px; cursor: pointer; font-weight: 500; font-size: 0.8rem;">Decline</button>
                  <button onclick="resolveApproval(${row.rowid}, 'ALLOW')" style="background: var(--primary); color: white; border: none; padding: 6px 14px; border-radius: 6px; cursor: pointer; font-weight: 500; font-size: 0.8rem;">Approve &amp; Execute</button>
                </div>
              ` : ''}
            </div>
          </div>
        `;
      }).join('');
    }

    function renderPolicyPanel() {
      const policy = state.policy || { exists: false, content: '', rules: [] };
      const rules = policy.rules || ['block_destructive_shell', 'require_approval_for_shell', 'allow_deploy_service', 'allow_deploy_cloud', 'require_approval_for_destructive_db'];
      
      els.policyRules.innerHTML = `
        <div style="display: flex; flex-wrap: wrap; gap: 10px;">
          ${rules.map((rule) => `
            <div style="background: var(--bg-main); border: 1px solid var(--border-color); border-radius: 8px; padding: 10px 14px; font-family: monospace; font-size: 0.85rem; display: flex; align-items: center; gap: 12px;">
              <span style="color: var(--primary); font-weight: 600;">${escapeHtml(rule)}</span>
              <span style="font-size: 0.65rem; background: rgba(16, 185, 129, 0.15); color: var(--allow); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(16, 185, 129, 0.3); font-weight: 700;">ACTIVE</span>
            </div>
          `).join('')}
        </div>
      `;
      els.policyPreview.textContent = policy.content || `version: "1.0"
policies:
  - name: block_destructive_shell
    description: "Hard blocks destructive shell commands containing rm -rf."
    tool_name: "run_shell"
    pattern: "rm -rf"
    action: BLOCK

  - name: require_approval_for_shell
    description: "Forces human verification for other shell commands."
    tool_name: "run_shell"
    action: REQUIRE_APPROVAL`;
    }

    function renderRegistry() {
      // Aggregate real stats from live state.logs
      const toolMap = new Map();
      state.logs.forEach(row => {
        const name = row.tool_name || 'unknown_tool';
        if (!toolMap.has(name)) {
          toolMap.set(name, { name, calls: 0, allowed: 0, blocked: 0 });
        }
        const stats = toolMap.get(name);
        stats.calls++;
        if (row.verdict === 'ALLOW') stats.allowed++;
        else stats.blocked++;
      });

      const tools = Array.from(toolMap.values());
      if (!tools.length) {
        // Fallback default structure if logs are empty
        tools.push(
          { name: "run_shell", calls: 1, allowed: 1, blocked: 0 },
          { name: "db_query", calls: 1, allowed: 0, blocked: 1 }
        );
      }

      els.toolRegistry.innerHTML = tools.map(tool => {
        const pct = tool.calls > 0 ? Math.round((tool.allowed / tool.calls) * 100) : 100;
        const radius = 22;
        const circumference = 2 * Math.PI * radius;
        const strokeDashoffset = circumference - (pct / 100) * circumference;

        return `
          <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px; display: flex; justify-content: space-between; align-items: center;">
            <div style="display: flex; flex-direction: column; gap: 8px;">
              <strong style="font-size: 1.05rem; color: var(--text-main); font-family: monospace;">${escapeHtml(tool.name)}</strong>
              <div style="font-size: 1.5rem; font-weight: 700; color: var(--text-main);">${formatNumber(tool.calls)} <span style="font-size: 0.85rem; font-weight: 400; color: var(--text-muted);">calls</span></div>
              <div class="muted" style="font-size: 0.75rem;">Allowed: ${tool.allowed} &nbsp;|&nbsp; Blocked: ${tool.blocked}</div>
            </div>
            <!-- Dynamic True SVG Percentage Progress Circle -->
            <div style="position: relative; width: 56px; height: 56px; display: flex; align-items: center; justify-content: center;">
              <svg width="56" height="56" style="transform: rotate(-90deg);">
                <circle cx="28" cy="28" r="${radius}" stroke="var(--border-color)" stroke-width="4" fill="none"></circle>
                <circle cx="28" cy="28" r="${radius}" stroke="var(--allow)" stroke-width="4" fill="none"
                  stroke-dasharray="${circumference}" stroke-dashoffset="${strokeDashoffset}" stroke-linecap="round"
                  style="transition: stroke-dashoffset 0.5s ease;"></circle>
              </svg>
              <span style="position: absolute; font-size: 0.7rem; font-weight: 700; color: var(--text-main);">${pct}%</span>
            </div>
          </div>
        `;
      }).join('');
    }

    function renderVirtualExplorer(rows) {
      const viewport = els.explorerViewport;
      const spacer = els.explorerSpacer;
      const windowEl = els.explorerWindow;

      if (!rows.length) {
        spacer.style.height = '0px';
        windowEl.innerHTML = '<div style="padding: 40px; text-align: center; color: var(--text-muted);">No records match your active filter settings.</div>';
        windowEl.style.transform = 'translateY(0)';
        els.explorerFooter.textContent = 'Viewing 0 records';
        return;
      }

      const totalHeight = rows.length * ROW_HEIGHT;
      spacer.style.height = `${totalHeight}px`;

      const scrollTop = viewport.scrollTop || 0;
      const viewportHeight = viewport.clientHeight || 550;
      const start = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
      const visibleCount = Math.ceil(viewportHeight / ROW_HEIGHT) + OVERSCAN * 2;
      const end = Math.min(rows.length, start + visibleCount);
      const slice = rows.slice(start, end);

      windowEl.style.transform = `translateY(${start * ROW_HEIGHT}px)`;
      windowEl.innerHTML = slice.map((row) => `
        <div class="table-row">
          <div class="table-cell muted">${escapeHtml(row.created_at)}</div>
          <div class="table-cell">${escapeHtml(row.agent_id)}</div>
          <div class="table-cell">${escapeHtml(row.tool_name)}</div>
          <div class="table-cell"><span class="${verdictClass(row.verdict)}">${escapeHtml(row.verdict)}</span></div>
          <div class="table-cell muted">${escapeHtml(row.triggered_rule || '—')}</div>
          <div class="table-cell muted">${formatLatency(row.latency_ms)}</div>
          <div class="table-cell muted">${escapeHtml(row.payload)}</div>
        </div>
      `).join('');

      els.explorerFooter.textContent = `Viewing 1-${Math.min(50, rows.length)} of ${formatNumber(rows.length)} records`;
    }

    function renderExplorer(rows) {
      requestAnimationFrame(() => renderVirtualExplorer(rows));
    }

    function updateVisiblePanels() {
      els.navButtons.forEach((button) => {
        button.classList.toggle('active', button.dataset.view === state.view);
      });
      els.panels.forEach((panel) => {
        panel.classList.toggle('is-visible', panel.dataset.viewPanel === state.view);
      });
      const titles = {
        'live-monitor': 'Live Activity Stream',
        'policy-panel': 'Security Guardrails',
        'tool-registry': 'Connected AI Tools',
        'audit-explorer': 'Activity History'
      };
      els.currentViewTitle.textContent = titles[state.view] || 'Dashboard';
    }

    function setView(view, persist = true) {
      state.view = view;
      if (persist) {
        location.hash = `#${view}`;
        persistState();
      }
      updateVisiblePanels();
      renderCurrentScope();
    }

    function renderCurrentScope() {
      const rows = filteredRows();
      renderFilterChips(rows);
      renderMetrics(rows);
      renderLiveFeed(rows);
      renderRegistry();
      renderPolicyPanel();
      renderExplorer(rows.slice(0, MAX_VIRTUAL_ROWS));
    }

    function queueRender() {
      if (state.renderQueued) return;
      state.renderQueued = true;
      requestAnimationFrame(() => {
        state.renderQueued = false;
        renderCurrentScope();
      });
    }

    function applyIncomingRows(newRows) {
      const normalized = newRows.map(normalizeRow);
      const currentIds = new Set(state.logs.map((row) => row.rowid));
      const merged = normalized.filter((row) => !currentIds.has(row.rowid)).concat(state.logs);
      state.logs = dedupeAndSort(merged).slice(0, MAX_VIRTUAL_ROWS);
      if (state.logs.length) {
        state.lastSeenRowId = Math.max(state.lastSeenRowId, state.logs[0].rowid || 0);
      }
      const latest = normalized[0];
      if (latest) {
        els.lastEventLabel.textContent = `Latest #${latest.rowid} • ${latest.tool_name}`;
      }
      queueRender();
    }

    async function bootstrap() {
      const response = await fetch(`/api/bootstrap?limit=${MAX_VIRTUAL_ROWS}`);
      const payload = await response.json();
      state.metrics = payload.metrics || null;
      state.logs = (payload.logs || []).map(normalizeRow);
      state.registry = payload.registry || [];
      state.policy = payload.policy || state.policy;
      state.lastSeenRowId = state.logs.length ? state.logs[0].rowid : 0;
      renderCurrentScope();
    }

    function startStream() {
      if (!('EventSource' in window)) return;
      const source = new EventSource(`/stream?since=${state.lastSeenRowId || 0}`);
      source.addEventListener('snapshot', (e) => {
        try {
          const p = JSON.parse(e.data);
          if (p.rows) applyIncomingRows(p.rows);
        } catch (_) {}
      });
      source.addEventListener('audit', (e) => {
        try {
          const p = JSON.parse(e.data);
          if (p.rows) applyIncomingRows(p.rows);
        } catch (_) {}
      });
    }

    function bindControls() {
      const applyAndPersist = () => {
        state.filters.verdict = els.filterVerdict.value;
        state.filters.agent_id = els.filterAgent.value;
        state.filters.rule_name = els.filterRule.value;
        state.filters.search = els.filterSearch.value;
        persistState();
        queueRender();
      };

      [els.filterVerdict, els.filterAgent, els.filterRule, els.filterSearch].forEach((el) => {
        el.addEventListener('input', applyAndPersist);
        el.addEventListener('change', applyAndPersist);
      });

      els.navButtons.forEach((btn) => {
        btn.addEventListener('click', () => setView(btn.dataset.view));
      });

      els.explorerViewport.addEventListener('scroll', () => {
        requestAnimationFrame(() => renderVirtualExplorer(filteredRows().slice(0, MAX_VIRTUAL_ROWS)));
      });
    }

    async function initialize() {
      restoreState();
      setView(state.view, false);
      els.filterVerdict.value = state.filters.verdict;
      els.filterAgent.value = state.filters.agent_id;
      els.filterRule.value = state.filters.rule_name;
      els.filterSearch.value = state.filters.search;
      bindControls();
      await bootstrap();
      startStream();
      renderCurrentScope();
    }

    initialize();
  </script>
</body>
</html>
"""

def _connect(db_path: str) -> sqlite3.Connection:
    return sqlite3.connect(db_path)


def _normalize_limit(limit: int) -> int:
    return max(1, min(int(limit), MAX_VIRTUAL_ROWS))


def _build_filters(
    verdict: Optional[str] = None,
    agent_id: Optional[str] = None,
    rule_name: Optional[str] = None,
    search: Optional[str] = None,
    after_rowid: int = 0,
) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []

    if after_rowid:
        clauses.append("rowid > ?")
        params.append(after_rowid)

    if verdict and verdict != "all":
        clauses.append("verdict = ?")
        params.append(verdict)

    if agent_id:
        clauses.append("agent_id = ?")
        params.append(agent_id)

    if rule_name:
        clauses.append("COALESCE(triggered_rule, '') = ?")
        params.append(rule_name)

    if search:
        like = f"%{search}%"
        clauses.append(
            "(tool_name LIKE ? OR agent_id LIKE ? OR payload LIKE ? OR COALESCE(triggered_rule, '') LIKE ? OR verdict LIKE ?)"
        )
        params.extend([like, like, like, like, like])

    if clauses:
        return " WHERE " + " AND ".join(clauses), params
    return "", params


def _serialize_row(row: AuditLogRow) -> dict[str, Any]:
    return {
        "rowid": row.rowid,
        "created_at": row.created_at,
        "agent_id": row.agent_id,
        "tool_name": row.tool_name,
        "payload": row.payload,
        "verdict": row.verdict,
        "triggered_rule": row.triggered_rule,
        "latency_ms": row.latency_ms,
    }


def _format_row_html(row: AuditLogRow) -> str:
    verdict_class = {
        "ALLOW": "verdict-allow",
        "BLOCK": "verdict-block",
        "REQUIRE_APPROVAL": "verdict-warning",
    }.get(row.verdict, "verdict-warning")

    return (
        '<tr class="table-row">'
        f'<div class="table-cell muted">{html.escape(row.created_at)}</div>'
        f'<div class="table-cell">{html.escape(row.agent_id)}</div>'
        f'<div class="table-cell">{html.escape(row.tool_name)}</div>'
        f'<div class="table-cell"><span class="{verdict_class}">{html.escape(row.verdict)}</span></div>'
        f'<div class="table-cell muted">{html.escape(row.triggered_rule or "—")}</div>'
        f'<div class="table-cell muted">{row.latency_ms:.2f} ms</div>'
        f'<div class="table-cell">{html.escape(row.payload)}</div>'
        "</tr>"
    )


def _format_rows_html(rows: Sequence[AuditLogRow]) -> str:
    if not rows:
        return (
            '<div class="empty-state">No audit records found. Run a guarded tool call to populate telemetry.</div>'
        )
    return "".join(_format_row_html(row) for row in rows)


def _aggregate_metrics(rows: Sequence[AuditLogRow]) -> DashboardMetrics:
    allowed = sum(1 for row in rows if row.verdict == "ALLOW")
    blocked = sum(1 for row in rows if row.verdict == "BLOCK")
    warning = max(len(rows) - allowed - blocked, 0)
    top_rules = Counter(row.triggered_rule for row in rows if row.triggered_rule).most_common(5)
    top_tools = Counter(row.tool_name for row in rows).most_common(8)
    unique_agents = len({row.agent_id for row in rows})
    unique_tools = len({row.tool_name for row in rows})
    return DashboardMetrics(
        total_calls=len(rows),
        allowed_calls=allowed,
        blocked_calls=blocked,
        warning_calls=warning,
        unique_agents=unique_agents,
        unique_tools=unique_tools,
        top_rules=top_rules,
        top_tools=top_tools,
    )


def _query_logs(
    db_path: str = DB_FILE,
    *,
    verdict: Optional[str] = None,
    agent_id: Optional[str] = None,
    rule_name: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = DEFAULT_LIMIT,
    after_rowid: int = 0,
    order: str = "desc",
) -> list[AuditLogRow]:
    if not os.path.exists(db_path):
        return []

    limit = _normalize_limit(limit)
    clause_sql, params = _build_filters(
        verdict=verdict,
        agent_id=agent_id,
        rule_name=rule_name,
        search=search,
        after_rowid=after_rowid,
    )
    direction = "ASC" if order.lower() == "asc" else "DESC"
    sql = (
        "SELECT rowid, created_at, agent_id, tool_name, payload, verdict, triggered_rule, latency_ms "
        "FROM audit_logs"
        f"{clause_sql} ORDER BY rowid {direction} LIMIT ?"
    )
    params.append(limit)

    with closing(_connect(db_path)) as connection:
        cursor = connection.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()

    return [
        AuditLogRow(
            rowid=int(row[0]),
            created_at=str(row[1]),
            agent_id=str(row[2]),
            tool_name=str(row[3]),
            payload=str(row[4]),
            verdict=str(row[5]),
            triggered_rule=row[6],
            latency_ms=float(row[7] or 0.0),
        )
        for row in rows
    ]


def _query_metrics(
    db_path: str = DB_FILE,
    *,
    verdict: Optional[str] = None,
    agent_id: Optional[str] = None,
    rule_name: Optional[str] = None,
    search: Optional[str] = None,
) -> DashboardMetrics:
    rows = _query_logs(
        db_path,
        verdict=verdict,
        agent_id=agent_id,
        rule_name=rule_name,
        search=search,
        limit=MAX_VIRTUAL_ROWS,
    )
    return _aggregate_metrics(rows)


def _query_registry(
    db_path: str = DB_FILE,
    *,
    verdict: Optional[str] = None,
    agent_id: Optional[str] = None,
    rule_name: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 12,
) -> list[ToolRegistryEntry]:
    rows = _query_logs(
        db_path,
        verdict=verdict,
        agent_id=agent_id,
        rule_name=rule_name,
        search=search,
        limit=MAX_VIRTUAL_ROWS,
    )
    registry: list[ToolRegistryEntry] = []
    by_tool: dict[str, list[AuditLogRow]] = {}
    for row in rows:
        by_tool.setdefault(row.tool_name, []).append(row)
    for tool_name, tool_rows in sorted(by_tool.items(), key=lambda item: (-len(item[1]), item[0]))[:limit]:
        registry.append(
            ToolRegistryEntry(
                tool_name=tool_name,
                calls=len(tool_rows),
                allowed=sum(1 for row in tool_rows if row.verdict == "ALLOW"),
                blocked=sum(1 for row in tool_rows if row.verdict == "BLOCK"),
                last_seen=max(row.created_at for row in tool_rows),
            )
        )
    return registry


def _read_policy_preview(policy_path: Path = POLICY_FILE) -> PolicyPreview:
    if not policy_path.exists():
        return PolicyPreview(
            exists=False,
            path=str(policy_path),
            content=(
                "No guardrails.yaml file found. Run `aegis init` to create a default policy scaffold for local monitoring."
            ),
            rules=[],
        )

    try:
        content = policy_path.read_text(encoding="utf-8")
    except OSError as exc:
        return PolicyPreview(
            exists=True,
            path=str(policy_path),
            content=f"Unable to read policy file: {exc}",
            rules=[],
        )

    rules = [match.group(1).strip() for match in re.finditer(r"^\s*-\s*name:\s*([A-Za-z0-9_\-]+)", content, re.MULTILINE)]
    return PolicyPreview(exists=True, path=str(policy_path), content=content, rules=rules)


def fetch_dashboard_state(
    db_path: str = DB_FILE,
    *,
    verdict: Optional[str] = None,
    agent_id: Optional[str] = None,
    rule_name: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = DEFAULT_LIMIT,
) -> DashboardSnapshot:
    logs = _query_logs(
        db_path,
        verdict=verdict,
        agent_id=agent_id,
        rule_name=rule_name,
        search=search,
        limit=limit,
    )
    return DashboardSnapshot(
        metrics=_aggregate_metrics(logs),
        logs=logs,
        registry=_query_registry(
            db_path,
            verdict=verdict,
            agent_id=agent_id,
            rule_name=rule_name,
            search=search,
        ),
        policy=_read_policy_preview(),
    )


def fetch_audit_data(db_path: Optional[str] = None):
    """Compatibility helper used by the existing dashboard tests."""

    snapshot = fetch_dashboard_state(db_path or DB_FILE, limit=50)
    if not snapshot.logs:
        return (
            0,
            0,
            0,
            '<div class="empty-state">No audit records or database found. Run a guarded pipeline first.</div>',
        )
    return (
        snapshot.metrics.total_calls,
        snapshot.metrics.allowed_calls,
        snapshot.metrics.blocked_calls,
        _format_rows_html(snapshot.logs),
    )


def calculate_dashboard_metrics(
    db_path: str = DB_FILE,
    *,
    verdict: Optional[str] = None,
    agent_id: Optional[str] = None,
    rule_name: Optional[str] = None,
    search: Optional[str] = None,
) -> DashboardMetrics:
    """Compatibility helper that returns aggregate metrics for the dashboard."""

    return _query_metrics(
        db_path,
        verdict=verdict,
        agent_id=agent_id,
        rule_name=rule_name,
        search=search,
    )


def _summary_payload(snapshot: DashboardSnapshot) -> dict[str, Any]:
    return {
        "metrics": asdict(snapshot.metrics),
        "logs": [_serialize_row(row) for row in snapshot.logs],
        "registry": [asdict(entry) for entry in snapshot.registry],
        "policy": asdict(snapshot.policy),
    }


def render_dashboard_html(db_file: str = DB_FILE) -> str:
    return HTML_TEMPLATE.replace("__DB_FILE__", html.escape(db_file))


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP handler for the local dashboard and its JSON/SSE endpoints."""

    db_path: str = DB_FILE

    def _set_security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline';")
        self.send_header("X-XSS-Protection", "1; mode=block")

    def _write_json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._set_security_headers()
        self.end_headers()
        self.wfile.write(body)

        def _set_security_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline';")
            self.send_header("X-XSS-Protection", "1; mode=block")

        self.end_headers()
        self.wfile.write(body)

    def _current_snapshot(self, params: dict[str, list[str]]) -> DashboardSnapshot:
        return fetch_dashboard_state(
            self.db_path,
            verdict=params.get("verdict", [None])[0],
            agent_id=params.get("agent_id", [None])[0],
            rule_name=params.get("rule_name", [None])[0],
            search=params.get("search", [None])[0],
            limit=int(params.get("limit", [DEFAULT_LIMIT])[0]),
        )

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path in {"/", "/index.html"}:
            page = render_dashboard_html(self.db_path).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self._set_security_headers()
            self.end_headers()
            self.wfile.write(page)
            return

        if parsed.path == "/api/bootstrap": 
            snapshot = self._current_snapshot(params)
            self._write_json(snapshot.as_json())
            return
        
        if parsed.path == "/api/logs":
            snapshot = self._current_snapshot(params)
            self._write_json({"logs": [_serialize_row(row) for row in snapshot.logs]})
            return

        if parsed.path == "/api/summary":
            snapshot = self._current_snapshot(params)
            self._write_json({"metrics": asdict(snapshot.metrics)})
            return

        if parsed.path == "/api/policy":
            self._write_json(asdict(_read_policy_preview()))
            return

        # === ADD THE APPROVAL ENDPOINT HERE ===
        # === UPDATE THE APPROVAL ENDPOINT FOR SECURITY ===
        if parsed.path == "/api/approve":
            # Optional: Check a simple bearer token or shared secret header
            auth_header = self.headers.get("Authorization", "")
            expected_token = os.environ.get("AEGIS_ADMIN_TOKEN", "")
            if expected_token and auth_header != f"Bearer {expected_token}":
                self._write_json({"success": False, "error": "Unauthorized"}, status=401)
                return

            try:
                rowid = int(params.get("rowid", [0])[0])
            except (ValueError, TypeError):
                self._write_json({"success": False, "error": "Invalid rowid format"}, status=400)
                return

            action = params.get("action", ["ALLOW"])[0].upper()
            if action not in {"ALLOW", "BLOCK"}:
                self._write_json({"success": False, "error": "Invalid action value"}, status=400)
                return
                
            new_verdict = "ALLOW" if action == "ALLOW" else "BLOCK"
            
            if rowid > 0:
                with closing(_connect(self.db_path)) as connection:
                    cursor = connection.cursor()
                    # Ensure the row exists before updating to prevent silent failures
                    cursor.execute("SELECT rowid FROM audit_logs WHERE rowid = ?", (rowid,))
                    if not cursor.fetchone():
                        self._write_json({"success": False, "error": "Record not found"}, status=404)
                        return

                    cursor.execute(
                        "UPDATE audit_logs SET verdict = ? WHERE rowid = ?",
                        (new_verdict, rowid)
                    )
                    connection.commit()
                self._write_json({"success": True, "rowid": rowid, "verdict": new_verdict})
            else:
                self._write_json({"success": False, "error": "Invalid rowid"}, status=400)
            return
        # ===============================================
    

        if parsed.path == "/stream":
            self._handle_stream(params)
            return

        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"404 Not Found")

    def _handle_stream(self, params: dict[str, list[str]]) -> None:
        since = int(params.get("since", [0])[0])
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        def write_event(event_name: str, payload: dict[str, Any]) -> None:
            message = f"event: {event_name}\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n".encode("utf-8")
            self.wfile.write(message)
            self.wfile.flush()

        try:
            initial = fetch_dashboard_state(self.db_path, limit=DEFAULT_LIMIT)
            write_event(
                "snapshot",
                {
                    "rows": [_serialize_row(row) for row in initial.logs],
                    "metrics": asdict(initial.metrics),
                    "registry": [asdict(entry) for entry in initial.registry],
                },
            )
            last_rowid = max((row.rowid for row in initial.logs), default=since)

            while True:
                rows = _query_logs(self.db_path, after_rowid=last_rowid, order="asc", limit=DEFAULT_LIMIT)
                if rows:
                    last_rowid = rows[-1].rowid
                    snapshot = fetch_dashboard_state(self.db_path, limit=DEFAULT_LIMIT)
                    write_event(
                        "audit",
                        {
                            "rows": [_serialize_row(row) for row in rows],
                            "metrics": asdict(snapshot.metrics),
                            "registry": [asdict(entry) for entry in snapshot.registry],
                        },
                    )
                else:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    time.sleep(STREAM_POLL_SECONDS)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return
        except Exception as exc:  # pragma: no cover - defensive stream guard
            try:
                write_event("error", {"message": str(exc)})
            except Exception:
                return

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003 - BaseHTTPRequestHandler API
        return


class _AegisThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True


def create_dashboard_server(host: str = "127.0.0.1", port: int = 8000, db_path: str = DB_FILE) -> ThreadingHTTPServer:
    handler = type("AegisDashboardHandler", (DashboardHandler,), {"db_path": db_path})
    return _AegisThreadingHTTPServer((host, port), handler)


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


if __name__ == "__main__":  # pragma: no cover
    run_dashboard()
