import json
import os
from datetime import datetime
from db import load_findings, load_runs


def generate_dashboard(output_path: str = "dashboard.html") -> str:
    all_findings = load_findings()
    all_runs = load_runs()

    total_findings = len(all_findings)
    total_runs = len(all_runs)
    high_count = sum(1 for f in all_findings if f["severity"] == "high")
    medium_count = sum(1 for f in all_findings if f["severity"] == "medium")
    low_count = sum(1 for f in all_findings if f["severity"] == "low")

    findings_json = json.dumps(all_findings)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>TRACEX Dashboard</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #f4f5f7; color: #1a1a2e; min-height: 100vh; }}
  .header {{ background: #1a1a2e; color: #fff; padding: 22px 40px; display: flex; align-items: center; justify-content: space-between; }}
  .header h1 {{ font-size: 20px; font-weight: 600; letter-spacing: 0.02em; }}
  .header .subtitle {{ font-size: 12px; color: #8892a4; margin-top: 3px; }}
  .header .meta {{ font-size: 11px; color: #8892a4; text-align: right; }}
  .container {{ padding: 32px 40px; max-width: 1300px; margin: 0 auto; }}
  .stat-row {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 28px; }}
  .stat-card {{ background: #fff; border-radius: 8px; padding: 18px 20px; border-top: 3px solid #e2e8f0; }}
  .stat-card.high {{ border-top-color: #b91c1c; }}
  .stat-card.medium {{ border-top-color: #b45309; }}
  .stat-card.low {{ border-top-color: #374151; }}
  .stat-card.total {{ border-top-color: #1a1a2e; }}
  .stat-card.runs {{ border-top-color: #1d4ed8; }}
  .stat-num {{ font-size: 32px; font-weight: 700; line-height: 1; }}
  .stat-label {{ font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 6px; }}
  .controls {{ background: #fff; border-radius: 8px; padding: 16px 20px; margin-bottom: 20px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }}
  .controls label {{ font-size: 12px; color: #6b7280; font-weight: 500; }}
  .time-tabs {{ display: flex; gap: 6px; }}
  .time-tab {{ padding: 6px 14px; border-radius: 20px; border: 1px solid #e2e8f0; font-size: 12px; cursor: pointer; background: #fff; transition: all 0.15s; }}
  .time-tab.active, .time-tab:hover {{ background: #1a1a2e; color: #fff; border-color: #1a1a2e; }}
  select, input[type=text] {{ padding: 7px 12px; border: 1px solid #e2e8f0; border-radius: 6px; font-size: 12px; background: #fff; color: #1a1a2e; outline: none; }}
  .controls-right {{ margin-left: auto; }}
  #search {{ width: 200px; }}
  .table-wrap {{ background: #fff; border-radius: 8px; overflow: hidden; }}
  .table-header {{ padding: 14px 20px; border-bottom: 1px solid #f1f3f5; display: flex; justify-content: space-between; align-items: center; }}
  .table-header span {{ font-size: 13px; font-weight: 600; }}
  .table-header .count {{ font-size: 12px; color: #6b7280; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
  th {{ padding: 10px 14px; text-align: left; background: #f8fafc; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: #6b7280; border-bottom: 1px solid #e2e8f0; cursor: pointer; user-select: none; }}
  th:hover {{ color: #1a1a2e; }}
  td {{ padding: 11px 14px; border-bottom: 1px solid #f1f3f5; vertical-align: top; }}
  tr:hover td {{ background: #f8fafc; cursor: pointer; }}
  tr.expanded td {{ background: #f0f4ff; }}
  .score-pill {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-weight: 700; font-size: 12px; color: #fff; }}
  .sev-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
  .sev-high {{ background: #fee2e2; color: #b91c1c; }}
  .sev-medium {{ background: #fef3c7; color: #b45309; }}
  .sev-low {{ background: #f3f4f6; color: #374151; }}
  .detail-row td {{ background: #f0f4ff !important; padding: 14px 20px; border-bottom: 2px solid #c7d2fe; }}
  .detail-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }}
  .detail-item label {{ display: block; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em; color: #6b7280; margin-bottom: 4px; }}
  .detail-item span {{ font-size: 12.5px; font-family: 'Courier New', monospace; word-break: break-all; }}
  .empty-state {{ text-align: center; padding: 60px 20px; color: #9ca3af; font-size: 14px; }}
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>TRACEX</h1>
    <div class="subtitle">Windows Event Log Detection Dashboard</div>
  </div>
  <div class="meta">Last updated: {generated}<br>{total_runs} analysis run(s) in database</div>
</div>

<div class="container">
  <div class="stat-row">
    <div class="stat-card total"><div class="stat-num" id="card-total">{total_findings}</div><div class="stat-label">Total Findings</div></div>
    <div class="stat-card runs"><div class="stat-num">{total_runs}</div><div class="stat-label">Runs Analyzed</div></div>
    <div class="stat-card high"><div class="stat-num" id="card-high">{high_count}</div><div class="stat-label">High Severity</div></div>
    <div class="stat-card medium"><div class="stat-num" id="card-medium">{medium_count}</div><div class="stat-label">Medium Severity</div></div>
    <div class="stat-card low"><div class="stat-num" id="card-low">{low_count}</div><div class="stat-label">Low Severity</div></div>
  </div>

  <div class="controls">
    <label>Time Range:</label>
    <div class="time-tabs">
      <button class="time-tab active" data-days="0" onclick="setTime(0)">All Time</button>
      <button class="time-tab" data-days="1" onclick="setTime(1)">24h</button>
      <button class="time-tab" data-days="7" onclick="setTime(7)">7 Days</button>
      <button class="time-tab" data-days="14" onclick="setTime(14)">14 Days</button>
      <button class="time-tab" data-days="30" onclick="setTime(30)">30 Days</button>
    </div>
    <label>Severity:</label>
    <select id="sev-filter" onchange="applyFilters()">
      <option value="">All</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
    </select>
    <label>Rule:</label>
    <select id="rule-filter" onchange="applyFilters()">
      <option value="">All Rules</option>
      <option value="brute_force_logon">Brute Force</option>
      <option value="suspicious_process_execution">Suspicious Process</option>
      <option value="privilege_escalation_sequence">Privilege Escalation</option>
      <option value="explicit_credential_use">Explicit Credential Use</option>
      <option value="account_modification">Account Modification</option>
    </select>
    <div class="controls-right">
      <input type="text" id="search" placeholder="Search descriptions..." oninput="applyFilters()">
    </div>
  </div>

  <div class="table-wrap">
    <div class="table-header">
      <span>Findings</span>
      <span class="count" id="result-count"></span>
    </div>
    <table>
      <thead>
        <tr>
          <th onclick="sortBy('score')">Score ↕</th>
          <th onclick="sortBy('rule_name')">Rule ↕</th>
          <th onclick="sortBy('severity')">Severity ↕</th>
          <th>MITRE ATT&CK</th>
          <th>Description</th>
          <th onclick="sortBy('run_at')">Timestamp ↕</th>
        </tr>
      </thead>
      <tbody id="findings-tbody"></tbody>
    </table>
    <div class="empty-state" id="empty-state" style="display:none">No findings match the current filters.</div>
  </div>
</div>

<script>
  const ALL_FINDINGS = {findings_json};
  let currentDays = 0;
  let sortCol = 'score';
  let sortDir = -1;

  function scoreColor(score) {{
    if (score >= 70) return '#b91c1c';
    if (score >= 40) return '#b45309';
    return '#374151';
  }}

  function sevBadge(sev) {{
    return `<span class="sev-badge sev-${{sev}}">${{sev}}</span>`;
  }}

  function setTime(days) {{
    currentDays = days;
    document.querySelectorAll('.time-tab').forEach(t => {{
      t.classList.toggle('active', parseInt(t.dataset.days) === days);
    }});
    applyFilters();
  }}

  function sortBy(col) {{
    if (sortCol === col) sortDir *= -1;
    else {{ sortCol = col; sortDir = -1; }}
    applyFilters();
  }}

  function applyFilters() {{
    const sevFilter = document.getElementById('sev-filter').value;
    const ruleFilter = document.getElementById('rule-filter').value;
    const search = document.getElementById('search').value.toLowerCase();
    const now = new Date();

    let filtered = ALL_FINDINGS.filter(f => {{
      if (sevFilter && f.severity !== sevFilter) return false;
      if (ruleFilter && f.rule_name !== ruleFilter) return false;
      if (search && !f.description.toLowerCase().includes(search)) return false;
      if (currentDays > 0) {{
        const diff = (now - new Date(f.run_at + 'Z')) / 86400000;
        if (diff > currentDays) return false;
      }}
      return true;
    }});

    filtered.sort((a, b) => {{
      let av = a[sortCol], bv = b[sortCol];
      if (typeof av === 'string') av = av.toLowerCase();
      if (typeof bv === 'string') bv = bv.toLowerCase();
      return av < bv ? sortDir : av > bv ? -sortDir : 0;
    }});

    document.getElementById('card-total').textContent = filtered.length;
    document.getElementById('card-high').textContent = filtered.filter(f => f.severity === 'high').length;
    document.getElementById('card-medium').textContent = filtered.filter(f => f.severity === 'medium').length;
    document.getElementById('card-low').textContent = filtered.filter(f => f.severity === 'low').length;
    renderTable(filtered);
  }}

  function renderTable(findings) {{
    const tbody = document.getElementById('findings-tbody');
    const empty = document.getElementById('empty-state');
    const count = document.getElementById('result-count');
    count.textContent = `${{findings.length}} finding${{findings.length !== 1 ? 's' : ''}}`;

    if (findings.length === 0) {{
      tbody.innerHTML = '';
      empty.style.display = 'block';
      return;
    }}
    empty.style.display = 'none';

    tbody.innerHTML = findings.map(f => {{
      const eventIds = JSON.parse(f.event_ids || '[]').join(', ');
      const mitre = f.mitre_technique ? `${{f.mitre_technique}} — ${{f.mitre_name}}` : 'N/A';
      const ts = f.run_at ? f.run_at.replace('T', ' ') : '';

      return `
        <tr onclick="toggleDetail(${{f.id}})">
          <td><span class="score-pill" style="background:${{scoreColor(f.score)}}">${{f.score}}</span></td>
          <td>${{f.rule_name}}</td>
          <td>${{sevBadge(f.severity)}}</td>
          <td>${{mitre}}</td>
          <td>${{f.description}}</td>
          <td style="color:#6b7280;font-size:11px;">${{ts}}</td>
        </tr>
        <tr class="detail-row" id="detail-${{f.id}}" style="display:none">
          <td colspan="6">
            <div class="detail-grid">
              <div class="detail-item"><label>Rule Name</label><span>${{f.rule_name}}</span></div>
              <div class="detail-item"><label>MITRE Technique</label><span>${{mitre}}</span></div>
              <div class="detail-item"><label>Confidence Score</label><span>${{f.score}} / 100</span></div>
              <div class="detail-item"><label>Severity</label><span>${{f.severity.toUpperCase()}}</span></div>
              <div class="detail-item"><label>Timestamp</label><span>${{ts}}</span></div>
              <div class="detail-item"><label>Event Record IDs</label><span>${{eventIds}}</span></div>
              <div class="detail-item" style="grid-column:1/-1"><label>Full Description</label><span>${{f.description}}</span></div>
            </div>
          </td>
        </tr>`;
    }}).join('');
  }}

  function toggleDetail(id) {{
    const detail = document.getElementById(`detail-${{id}}`);
    const isOpen = detail.style.display !== 'none';
    detail.style.display = isOpen ? 'none' : 'table-row';
  }}

  applyFilters();
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path