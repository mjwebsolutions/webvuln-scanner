# reporter.py
# generates a clean HTML report from all scan results
# spent embarrassingly long on the CSS ngl but it looks fire now

from datetime import datetime


def generate_html_report(target_url, header_results, sqli_vulns, xss_vulns, dir_results, output_file="reports/report.html"):
    """
    takes all scan results and bakes them into a nice HTML report
    something you can actually show people without it looking like raw terminal output lol
    """

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_vulns = len(sqli_vulns) + len(xss_vulns)
    grade = header_results.get('grade', 'N/A') if header_results else 'N/A'

    # color the grade cuz A should look good and F should look scary
    grade_colors = {'A': '#27ae60', 'B': '#2ecc71', 'C': '#f39c12', 'D': '#e67e22', 'F': '#e74c3c'}
    grade_color = grade_colors.get(grade, '#888')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebVuln Scanner Report - {target_url}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 30px 20px; }}
        header {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 30px; margin-bottom: 25px; }}
        header h1 {{ font-size: 1.8rem; color: #58a6ff; margin-bottom: 8px; }}
        header p {{ color: #8b949e; font-size: 0.95rem; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; }}
        .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }}
        .stat-card .number {{ font-size: 2.5rem; font-weight: bold; }}
        .stat-card .label {{ color: #8b949e; font-size: 0.85rem; margin-top: 5px; }}
        .red {{ color: #f85149; }} .orange {{ color: #e67e22; }} .green {{ color: #3fb950; }} .blue {{ color: #58a6ff; }}
        .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }}
        .section-header {{ background: #21262d; padding: 15px 20px; font-weight: bold; font-size: 1rem; border-bottom: 1px solid #30363d; }}
        .section-body {{ padding: 20px; }}
        .vuln-card {{ background: #0d1117; border-left: 4px solid #f85149; border-radius: 4px; padding: 15px; margin-bottom: 12px; }}
        .vuln-card.medium {{ border-left-color: #e67e22; }}
        .vuln-card.low {{ border-left-color: #f0c14b; }}
        .vuln-card h4 {{ color: #f85149; margin-bottom: 8px; }}
        .vuln-card.medium h4 {{ color: #e67e22; }}
        .vuln-card.low h4 {{ color: #f0c14b; }}
        .vuln-card p {{ font-size: 0.88rem; margin: 3px 0; }}
        .vuln-card code {{ background: #21262d; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 0.82rem; word-break: break-all; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: bold; margin-left: 8px; }}
        .badge-high {{ background: #f8514920; color: #f85149; border: 1px solid #f85149; }}
        .badge-medium {{ background: #e67e2220; color: #e67e22; border: 1px solid #e67e22; }}
        .badge-low {{ background: #f0c14b20; color: #f0c14b; border: 1px solid #f0c14b; }}
        .grade-badge {{ font-size: 3rem; font-weight: bold; color: {grade_color}; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
        th {{ background: #21262d; padding: 10px 12px; text-align: left; color: #8b949e; font-weight: 600; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #21262d; }}
        tr:last-child td {{ border-bottom: none; }}
        .status-200 {{ color: #3fb950; }} .status-301, .status-302 {{ color: #58a6ff; }} .status-403 {{ color: #e67e22; }}
        .no-issues {{ color: #3fb950; text-align: center; padding: 20px; font-style: italic; }}
        .disclaimer {{ background: #161b22; border: 1px solid #f0c14b40; border-radius: 8px; padding: 15px 20px; margin-top: 25px; font-size: 0.82rem; color: #8b949e; }}
        .disclaimer strong {{ color: #f0c14b; }}
        footer {{ text-align: center; margin-top: 25px; color: #484f58; font-size: 0.82rem; }}
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>🔐 WebVuln Scanner Report</h1>
        <p><strong>Target:</strong> {target_url}</p>
        <p><strong>Scan Time:</strong> {timestamp}</p>
    </header>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="number {'red' if total_vulns > 0 else 'green'}">{total_vulns}</div>
            <div class="label">Total Vulnerabilities</div>
        </div>
        <div class="stat-card">
            <div class="number red">{len(sqli_vulns)}</div>
            <div class="label">SQL Injection</div>
        </div>
        <div class="stat-card">
            <div class="number orange">{len(xss_vulns)}</div>
            <div class="label">XSS Findings</div>
        </div>
        <div class="stat-card">
            <div class="grade-badge">{grade}</div>
            <div class="label">Header Security Grade</div>
        </div>
    </div>
"""

    # --- SQLi section ---
    html += """
    <div class="section">
        <div class="section-header">💉 SQL Injection Results</div>
        <div class="section-body">
"""
    if sqli_vulns:
        for v in sqli_vulns:
            html += f"""
            <div class="vuln-card">
                <h4>SQL Injection Detected <span class="badge badge-high">HIGH</span></h4>
                <p><strong>URL:</strong> <code>{v['url']}</code></p>
                <p><strong>Method:</strong> {v['method']}</p>
                <p><strong>Payload:</strong> <code>{v['payload']}</code></p>
                <p><strong>Evidence:</strong> {v['evidence']}</p>
            </div>"""
    else:
        html += '<p class="no-issues">✅ No SQL injection vulnerabilities detected</p>'

    html += "</div></div>"

    # --- XSS section ---
    html += """
    <div class="section">
        <div class="section-header">⚡ Cross-Site Scripting (XSS) Results</div>
        <div class="section-body">
"""
    if xss_vulns:
        for v in xss_vulns:
            html += f"""
            <div class="vuln-card">
                <h4>Reflected XSS Detected <span class="badge badge-high">HIGH</span></h4>
                <p><strong>URL:</strong> <code>{v['url']}</code></p>
                <p><strong>Method:</strong> {v['method']}</p>
                <p><strong>Payload:</strong> <code>{v['payload'][:80]}</code></p>
                <p><strong>Evidence:</strong> {v['evidence']}</p>
            </div>"""
    else:
        html += '<p class="no-issues">✅ No reflected XSS vulnerabilities detected</p>'

    html += "</div></div>"

    # --- Headers section ---
    html += """
    <div class="section">
        <div class="section-header">🛡️ Security Headers Audit</div>
        <div class="section-body">
"""
    if header_results:
        missing = header_results.get('missing', [])
        present = header_results.get('present', [])
        info_leaks = header_results.get('info_leaks', [])

        if missing:
            html += "<h4 style='margin-bottom:12px; color:#f85149'>Missing Headers</h4>"
            for h in missing:
                badge_class = f"badge-{h['severity'].lower()}"
                html += f"""
                <div class="vuln-card {'medium' if h['severity']=='MEDIUM' else 'low' if h['severity']=='LOW' else ''}">
                    <h4>{h['header']} <span class="badge {badge_class}">{h['severity']}</span></h4>
                    <p>{h['description']}</p>
                    <p><strong>Fix:</strong> <code>{h['recommendation']}</code></p>
                </div>"""

        if info_leaks:
            html += "<h4 style='margin: 16px 0 12px; color:#e67e22'>Info Leaking Headers</h4>"
            for l in info_leaks:
                html += f"""
                <div class="vuln-card medium">
                    <h4>{l['header']}</h4>
                    <p><strong>Value:</strong> <code>{l['value']}</code></p>
                    <p>{l['note']}</p>
                </div>"""

        if present:
            html += f"<p style='margin-top:16px; color:#3fb950'>✅ {len(present)} security header(s) properly configured</p>"
    else:
        html += '<p class="no-issues">Header check did not run or failed</p>'

    html += "</div></div>"

    # --- Directory bruteforce section ---
    accessible = [d for d in dir_results if d['status'] == 200] if dir_results else []
    html += f"""
    <div class="section">
        <div class="section-header">📁 Directory Discovery ({len(dir_results) if dir_results else 0} paths found)</div>
        <div class="section-body">
"""
    if dir_results:
        html += """<table><thead><tr><th>URL</th><th>Status</th><th>Note</th></tr></thead><tbody>"""
        for d in dir_results:
            status_class = f"status-{d['status']}"
            html += f"<tr><td><code>{d['url']}</code></td><td class='{status_class}'>{d['status']}</td><td>{d['note']}</td></tr>"
        html += "</tbody></table>"
    else:
        html += '<p class="no-issues">No notable directories discovered</p>'

    html += "</div></div>"

    html += f"""
    <div class="disclaimer">
        <strong>⚠️ Legal Disclaimer:</strong> This tool is intended for educational purposes and authorized 
        security testing only. Only use this on systems you own or have explicit written permission to test. 
        Running this against systems without authorization is illegal and unethical. The author is not 
        responsible for any misuse or damage caused by this tool. Stay legal out here.
    </div>

    <footer>Generated by WebVuln Scanner | {timestamp}</footer>
</div>
</body>
</html>"""

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"\n[+] report saved to {output_file}")
        return output_file
    except Exception as e:
        print(f"[!] couldn't save report: {e}")
        return None
