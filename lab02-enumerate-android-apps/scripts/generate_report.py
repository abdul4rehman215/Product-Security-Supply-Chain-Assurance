#!/usr/bin/env python3
import json
import sys
from datetime import datetime
from pathlib import Path

def html_escape(s):
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )

def generate_html_report(json_file, output_file):
    """
    Generate HTML report from JSON analysis results

    - Read JSON analysis file
    - Create HTML structure with:
      - Header with APK info and summary
      - Critical findings section
      - APK information table
      - Security recommendations
      - Analysis details from each tool
    - Write HTML to output file

    HTML includes:
    - Professional styling with CSS
    - Color-coded severity levels
    - Tables for structured data
    - Lists for findings and recommendations
    """
    with open(json_file, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    apk_info = data.get("apk_info", {})
    summary = data.get("summary", {})
    apktool_analysis = data.get("apktool_analysis", {})
    jadx_analysis = data.get("jadx_analysis", {})
    apkleaks_analysis = data.get("apkleaks_analysis", {})

    total_issues = summary.get("total_issues", 0)
    critical_findings = summary.get("critical_findings", [])
    recommendations = summary.get("recommendations", [])

    # Severity badge based on total_issues (simple)
    if total_issues >= 15:
        sev_class = "sev-high"
        sev_label = "HIGH"
    elif total_issues >= 5:
        sev_class = "sev-med"
        sev_label = "MEDIUM"
    else:
        sev_class = "sev-low"
        sev_label = "LOW"

    now = datetime.utcnow().isoformat() + "Z"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>APK Security Analysis Report</title>
<style>
    body {{
        font-family: Arial, sans-serif;
        margin: 0;
        background: #f5f7fb;
        color: #1f2937;
    }}
    header {{
        background: #111827;
        color: white;
        padding: 24px;
    }}
    .container {{
        max-width: 1100px;
        margin: 0 auto;
        padding: 18px;
    }}
    .card {{
        background: white;
        border-radius: 10px;
        padding: 18px;
        margin: 14px 0;
        box-shadow: 0 2px 8px rgba(0,0,0,0.06);
    }}
    h1, h2, h3 {{
        margin: 0 0 10px 0;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin-top: 10px;
    }}
    th, td {{
        text-align: left;
        padding: 10px;
        border-bottom: 1px solid #e5e7eb;
        vertical-align: top;
    }}
    th {{
        background: #f3f4f6;
    }}
    ul {{
        margin: 8px 0 0 18px;
    }}
    .badge {{
        display: inline-block;
        padding: 6px 10px;
        border-radius: 999px;
        font-weight: bold;
        font-size: 12px;
        color: white;
    }}
    .sev-high {{ background: #dc2626; }}
    .sev-med  {{ background: #f59e0b; }}
    .sev-low  {{ background: #16a34a; }}

    .muted {{
        color: #6b7280;
        font-size: 13px;
    }}
    .code {{
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
        font-size: 13px;
        background: #0b1020;
        color: #e5e7eb;
        padding: 10px;
        border-radius: 8px;
        overflow-x: auto;
    }}
</style>
</head>
<body>
<header>
  <div class="container">
    <h1>APK Security Analysis Report</h1>
    <p class="muted">Generated: {html_escape(now)}</p>
    <p><span class="badge {sev_class}">Overall Severity: {html_escape(sev_label)}</span></p>
  </div>
</header>

<div class="container">

  <div class="card">
    <h2>Summary</h2>
    <p><b>Total Issues:</b> {html_escape(total_issues)}</p>
  </div>

  <div class="card">
    <h2>APK Information</h2>
    <table>
      <tr><th>Package Name</th><td>{html_escape(apk_info.get('package_name'))}</td></tr>
      <tr><th>Version Code</th><td>{html_escape(apk_info.get('version_code'))}</td></tr>
      <tr><th>Version Name</th><td>{html_escape(apk_info.get('version_name'))}</td></tr>
      <tr><th>Tool</th><td>{html_escape(apk_info.get('tool'))}</td></tr>
      <tr><th>Timestamp</th><td>{html_escape(apk_info.get('timestamp'))}</td></tr>
      <tr><th>Notes / Errors</th><td>{html_escape(apk_info.get('error', ''))}<br>{html_escape(apk_info.get('note',''))}</td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Critical Findings</h2>
    {"<p>No critical findings reported.</p>" if not critical_findings else "<ul>" + "".join(f"<li>{html_escape(x)}</li>" for x in critical_findings) + "</ul>"}
  </div>

  <div class="card">
    <h2>Recommendations</h2>
    {"<p>No recommendations generated.</p>" if not recommendations else "<ul>" + "".join(f"<li>{html_escape(x)}</li>" for x in recommendations) + "</ul>"}
  </div>

  <div class="card">
    <h2>apktool Analysis</h2>
    <p><b>Status:</b> {html_escape(apktool_analysis.get('decompile_status'))}</p>
    <p><b>Manifest:</b> {html_escape(apktool_analysis.get('manifest_path'))}</p>
    <h3>Issues</h3>
    {"<p>No issues found by manifest checks.</p>" if not apktool_analysis.get('issues') else "<ul>" + "".join(f"<li>{html_escape(x)}</li>" for x in apktool_analysis.get('issues', [])) + "</ul>"}
    {f"<h3>Errors</h3><div class='code'>{html_escape(apktool_analysis.get('stderr',''))}</div>" if apktool_analysis.get('stderr') else ""}
  </div>

  <div class="card">
    <h2>JADX Analysis</h2>
    <p><b>Status:</b> {html_escape(jadx_analysis.get('decompile_status'))}</p>
    <p><b>Output Directory:</b> {html_escape(jadx_analysis.get('output_dir'))}</p>
    <p><b>Java File Count:</b> {html_escape(jadx_analysis.get('java_file_count'))}</p>
    {f"<h3>Errors</h3><div class='code'>{html_escape(jadx_analysis.get('stderr',''))}</div>" if jadx_analysis.get('stderr') else ""}
  </div>

  <div class="card">
    <h2>apkleaks Analysis</h2>
    <p><b>Status:</b> {html_escape(apkleaks_analysis.get('run_status'))}</p>
    <p><b>JSON Report:</b> {html_escape(apkleaks_analysis.get('json_report'))}</p>
    <p><b>Secrets Found:</b> {html_escape(apkleaks_analysis.get('secrets_count'))}</p>
    {f"<h3>Errors</h3><div class='code'>{html_escape(apkleaks_analysis.get('stderr',''))}</div>" if apkleaks_analysis.get('stderr') else ""}
  </div>

</div>

</body>
</html>
"""

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 generate_report.py <json_file> <output_html>")
        sys.exit(1)

    json_file = sys.argv[1]
    output_html = sys.argv[2]

    if not Path(json_file).is_file():
        print(f"[-] Input JSON file not found: {json_file}")
        sys.exit(1)

    generate_html_report(json_file, output_html)
    print(f"[+] HTML report generated: {output_html}")

if __name__ == "__main__":
    main()
