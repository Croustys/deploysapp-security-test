#!/usr/bin/env python3
"""
Aggregate all raw JSON findings into a unified HTML security report.
"""
import json
import os
import glob
from datetime import datetime

RAW_DIR = os.path.join(os.path.dirname(__file__), '..', 'reports', 'raw')
HTML_DIR = os.path.join(os.path.dirname(__file__), '..', 'reports', 'html')
os.makedirs(HTML_DIR, exist_ok=True)

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'warning': 5}
SEVERITY_COLORS = {
    'critical': '#dc2626', 'high': '#ea580c',
    'medium':   '#d97706', 'low':  '#65a30d',
    'info':     '#0284c7', 'warning': '#7c3aed'
}

def load_reports():
    all_findings = []
    summaries = {}
    for path in sorted(glob.glob(os.path.join(RAW_DIR, '*.json'))):
        try:
            with open(path) as f:
                data = json.load(f)
            category = data.get('category', os.path.basename(path))
            findings = data.get('findings', [])
            all_findings.extend(findings)
            summaries[category] = data.get('summary', {})
        except Exception as e:
            print(f"[warn] Could not load {path}: {e}")
    return all_findings, summaries

def severity_badge(sev):
    color = SEVERITY_COLORS.get(sev, '#6b7280')
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold;text-transform:uppercase">{sev}</span>'

def build_html(findings, summaries):
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in findings:
        sev = f.get('severity', 'info').lower()
        counts[sev] = counts.get(sev, 0) + 1

    vuln_findings = [f for f in findings if f.get('status') == 'vulnerable']
    vuln_findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get('severity','info'), 99))

    # Executive summary cards
    summary_cards = ''.join(f'''
        <div style="background:{SEVERITY_COLORS.get(s,'#6b7280')};color:white;padding:20px;border-radius:8px;text-align:center;min-width:100px">
            <div style="font-size:36px;font-weight:bold">{counts.get(s,0)}</div>
            <div style="font-size:14px;text-transform:uppercase">{s}</div>
        </div>''' for s in ['critical','high','medium','low','info'])

    # Category summary table
    cat_rows = ''
    for cat, summ in sorted(summaries.items()):
        failed = summ.get('failed', 0)
        passed = summ.get('passed', 0)
        status_color = '#dc2626' if failed > 0 else '#16a34a'
        status_text  = f'⚠ {failed} FAILED' if failed > 0 else '✓ All passed'
        cat_rows += f'''
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{cat}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;color:{status_color};font-weight:bold">{status_text}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{passed + failed}</td>
        </tr>'''

    # Findings table
    finding_rows = ''
    for idx, f in enumerate(vuln_findings):
        sev   = f.get('severity','info').lower()
        cwe   = f.get('cwe','')
        cvss  = f.get('cvss','')
        remed = f.get('remediation','—')
        evidence = f.get('evidence','—')
        endpoint = f.get('endpoint','')
        finding_rows += f'''
        <tr style="border-bottom:1px solid #e5e7eb">
            <td style="padding:10px 12px;font-family:monospace;font-size:12px">{f.get('id','')}</td>
            <td style="padding:10px 12px">{severity_badge(sev)}</td>
            <td style="padding:10px 12px;font-weight:500">{f.get('title','')}</td>
            <td style="padding:10px 12px;font-size:12px;color:#6b7280">{evidence}</td>
            <td style="padding:10px 12px;font-size:12px">{cwe}</td>
            <td style="padding:10px 12px;font-size:12px;color:#374151">{remed}</td>
        </tr>'''

    if not finding_rows:
        finding_rows = '<tr><td colspan="6" style="padding:20px;text-align:center;color:#6b7280">No vulnerabilities found</td></tr>'

    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    total_vulns = len(vuln_findings)

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Deploysapp Security Report — {timestamp}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin:0; padding:24px; background:#f9fafb; color:#111827 }}
  h1 {{ font-size:24px; margin:0 0 4px }}
  h2 {{ font-size:18px; margin:24px 0 12px; border-bottom:2px solid #e5e7eb; padding-bottom:6px }}
  table {{ width:100%; border-collapse:collapse; background:white; border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.1) }}
  th {{ background:#1e293b; color:white; padding:10px 12px; text-align:left; font-size:13px }}
  tr:hover {{ background:#f1f5f9 }}
  .card-row {{ display:flex; gap:16px; flex-wrap:wrap; margin:16px 0 }}
  .warn {{ background:#fef3c7; border-left:4px solid #d97706; padding:12px 16px; border-radius:4px; margin:16px 0 }}
</style>
</head>
<body>
<h1>Deploysapp.com — Pre-Launch Security Report</h1>
<p style="color:#6b7280">Generated: {timestamp} | Total vulnerabilities found: <strong>{total_vulns}</strong></p>

{('<div class="warn">⚠ <strong>CRITICAL vulnerabilities found — DO NOT launch until resolved.</strong></div>' if counts.get('critical',0) > 0 else '')}

<h2>Executive Summary</h2>
<div class="card-row">{summary_cards}</div>

<h2>Test Category Summary</h2>
<table>
  <thead><tr><th>Category</th><th>Status</th><th>Total Checks</th></tr></thead>
  <tbody>{cat_rows or '<tr><td colspan="3" style="padding:20px;text-align:center">No categories scanned yet</td></tr>'}</tbody>
</table>

<h2>Vulnerability Findings ({total_vulns})</h2>
<table>
  <thead>
    <tr>
      <th>ID</th><th>Severity</th><th>Title</th>
      <th>Evidence</th><th>CWE</th><th>Remediation</th>
    </tr>
  </thead>
  <tbody>{finding_rows}</tbody>
</table>

<p style="margin-top:32px;color:#9ca3af;font-size:12px">
  Generated by deploysapp-security-test project.
  All target services are intentionally vulnerable — do not use in production.
</p>
</body>
</html>'''


def main():
    findings, summaries = load_reports()
    html = build_html(findings, summaries)
    out_path = os.path.join(HTML_DIR, 'security-report.html')
    with open(out_path, 'w') as f:
        f.write(html)
    total = len([x for x in findings if x.get('status') == 'vulnerable'])
    print(f"Report generated: {out_path}")
    print(f"Total vulnerabilities: {total}")
    if any(x.get('severity') == 'critical' and x.get('status') == 'vulnerable' for x in findings):
        print("⚠  CRITICAL vulnerabilities found — review before launch")


if __name__ == '__main__':
    main()
