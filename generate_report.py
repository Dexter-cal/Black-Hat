import json
import sys
import html
import random

# Remediation Intelligence Database
REMEDIATION_DB = {
    "Potential SQL Injection": {"remediation": "Use prepared statements and parameterized queries. Implement strict input validation.", "severity": "CRITICAL"},
    "Potential Cross-Site Scripting (XSS)": {"remediation": "Implement output encoding for all user-supplied data. Use Content Security Policy (CSP).", "severity": "HIGH"},
    "Potential Directory Traversal": {"remediation": "Validate and sanitize all file paths. Use indirect references for file access.", "severity": "HIGH"},
    "Potential Command Injection": {"remediation": "Avoid executing system commands with user input. Use safe APIs or strict whitelisting.", "severity": "CRITICAL"},
    "Exposed Git repository confirmed": {"remediation": "Restrict access to the .git directory or remove it from the web server root.", "severity": "HIGH"},
    "Deprecated TLS version detected": {"remediation": "Disable TLS 1.0 and 1.1. Upgrade to TLS 1.2 or 1.3.", "severity": "MEDIUM"},
    "Weak cipher suite detected": {"remediation": "Disable weak ciphers (e.g., 3DES, RC4). Prioritize AEAD ciphers like AES-GCM.", "severity": "MEDIUM"},
    "Sensitive environment variables exposed": {"remediation": "Ensure .env files are not accessible via the web server. Move secrets to a secure vault.", "severity": "CRITICAL"},
    "Process executing from deleted file": {"remediation": "Immediate investigation required. This is a high-confidence indicator of RAM-resident malware.", "severity": "CRITICAL"},
    "memfd_create usage detected": {"remediation": "Audit the process using anonymous memory. memfd is frequently used for fileless execution.", "severity": "HIGH"},
    "EDR/AV detected": {"remediation": "Verify security software is correctly configured and alerting. Monitor for evasion attempts.", "severity": "INFO"},
    "Vulnerable package version": {"remediation": "Upgrade the identified package to the latest secure version in the manifest.", "severity": "HIGH"},
    "Kernel escalation risk": {"remediation": "Patch the host kernel to the latest version. Disable unprivileged user namespaces if not required.", "severity": "CRITICAL"}
}

def get_remediation(finding_text):
    for key, value in REMEDIATION_DB.items():
        if key.lower() in finding_text.lower():
            return value
    return {"remediation": "Perform manual review and follow industry best practices.", "severity": "INFO"}

def generate_html(data, output_file):
    target = html.escape(str(data.get('target', 'Unknown')))
    html_content = f"""
    <html>
    <head>
        <title>OmniStrike Apex Dashboard - {target}</title>
        <style>
            :root {{
                --bg-primary: #0a0a0c;
                --bg-secondary: #121216;
                --accent: #00ff41; /* Terminal Green */
                --accent-dim: #003b0f;
                --text-primary: #e0e0e0;
                --text-secondary: #a0a0a0;
                --border: #2a2a30;
                --danger: #ff3e3e;
                --warning: #ffcc00;
                --info: #00ccff;
            }}
            body {{
                font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: var(--bg-primary);
                color: var(--text-primary);
                line-height: 1.6;
                margin: 0;
                padding: 0;
            }}
            .sidebar {{
                width: 250px;
                position: fixed;
                height: 100vh;
                background: var(--bg-secondary);
                border-right: 1px solid var(--border);
                padding: 20px;
            }}
            .main-content {{
                margin-left: 290px;
                padding: 40px;
                max-width: 1400px;
            }}
            .card {{
                background: var(--bg-secondary);
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 24px;
                margin-bottom: 24px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }}
            h1, h2, h3 {{ color: var(--accent); font-weight: 300; letter-spacing: 1px; }}
            h1 {{ border-bottom: 1px solid var(--accent-dim); padding-bottom: 10px; margin-bottom: 30px; font-size: 2.5em; }}
            .section-header {{ display: flex; align-items: center; margin-bottom: 20px; }}
            .section-header h2 {{ margin: 0; }}
            .status-indicator {{
                width: 12px; height: 12px; border-radius: 50%; background: var(--accent);
                margin-right: 15px; box-shadow: 0 0 10px var(--accent);
            }}
            .finding {{
                padding: 20px; margin: 15px 0; border-radius: 6px; border: 1px solid var(--border);
                background: rgba(255,255,255,0.02); position: relative;
            }}
            .severity-badge {{
                position: absolute; top: 15px; right: 20px; padding: 4px 12px; border-radius: 4px;
                font-weight: bold; font-size: 0.75em; text-transform: uppercase;
            }}
            .CRITICAL {{ background-color: var(--danger); color: #fff; box-shadow: 0 0 8px var(--danger); }}
            .HIGH {{ background-color: #d35400; color: #fff; }}
            .MEDIUM {{ background-color: var(--warning); color: #000; }}
            .INFO {{ background-color: var(--info); color: #fff; }}
            .remediation {{ margin-top: 15px; padding: 15px; background: var(--bg-primary); border-radius: 4px; border-left: 3px solid var(--accent); }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid var(--border); }}
            th {{ color: var(--text-secondary); font-size: 0.9em; }}
            pre {{ background: #000; color: #0f0; padding: 15px; border-radius: 4px; overflow-x: auto; font-family: 'Courier New', Courier, monospace; }}
            code {{ background: rgba(0,255,65,0.1); color: var(--accent); padding: 2px 4px; border-radius: 3px; }}
            .map-sim {{ height: 200px; background: url('https://upload.wikimedia.org/wikipedia/commons/e/ec/World_Map_Blank.svg') center center; filter: invert(1) brightness(0.5) sepia(1) hue-rotate(80deg); opacity: 0.3; }}
        </style>
    </head>
    <body>
        <div class="sidebar">
            <h2 style="color: var(--accent)">OMNISTRIKE APEX</h2>
            <div style="font-size: 0.8em; color: var(--text-secondary); margin-bottom: 30px;">Adv Adversary Emulation Suite</div>
            <div style="margin-bottom: 10px;">• TARGET: {target}</div>
            <div style="margin-bottom: 10px;">• UPTIME: 100%</div>
            <div style="margin-bottom: 10px;">• NODES: {len(data.get('compromised_hosts', {}))} compromised</div>
            <div style="margin-bottom: 10px;">• PROXIES: ACTIVE</div>
        </div>
        <div class="main-content">
            <h1>COMMAND CENTER: OPERATION {target.upper()}</h1>

            <div class="card">
                <div class="section-header">
                    <div class="status-indicator"></div>
                    <h2>Real-Time Surveillance Overview</h2>
                </div>
                <div class="map-sim"></div>
                <p>Digital Shadow established. Autonomous monitoring active.</p>
            </div>

            <div class="card">
                <h2>Network Intelligence & Discovery</h2>
                <table>
                    <tr><th>Node / Host</th><th>OS Identity</th><th>Surface (Ports)</th><th>Active Banner</th></tr>
    """

    open_ports = data.get('open_ports', {})
    fingerprints = data.get('fingerprints', {})
    for ip, ports in open_ports.items():
        for port, banner in ports.items():
            html_content += f"""
            <tr>
                <td>{html.escape(str(ip))}</td>
                <td>{html.escape(str(fingerprints.get(ip, 'Unknown')))}</td>
                <td><code>{html.escape(str(port))}</code></td>
                <td><code>{html.escape(str(banner or 'N/A'))}</code></td>
            </tr>"""
    html_content += "</table></div>"

    # Polymorphic Engine
    poly = data.get('polymorphic_output', '')
    if poly:
        html_content += '<div class="card"><h2>Polymorphic Engine: Code Morphing Preview</h2>'
        html_content += f"""
        <div class="finding info">
            <strong>Self-Rewriting Logic (Polymorphic Output):</strong><br>
            <pre>{html.escape(poly)}</pre>
        </div>"""
        html_content += '</div>'

    # Messaging
    messaging = data.get('messaging_artifacts', {})
    if messaging:
        html_content += '<div class="card"><h2>Shadow Intel: Messaging App Data</h2>'
        for ip, findings in messaging.items():
            for f in findings:
                html_content += f"""
                <div class="finding info">
                    <span class="severity-badge INFO">SURVEILLANCE</span>
                    <strong>{html.escape(f['app'])} ({html.escape(f['storage_type'])})</strong><br>
                    PATH: <code>{html.escape(f['path'])}</code>
                    <pre>{html.escape(f['metadata'])}</pre>
                </div>"""
        html_content += '</div>'

    # Behavioral AI
    ai = data.get('ai_orchestration', {})
    if ai:
        html_content += '<div class="card"><h2>Behavioral AI: Autonomous Decision Engine</h2>'
        html_content += f"""
        <div class="finding info">
            <span class="severity-badge INFO">AI_MODE</span>
            <strong>MODE: {html.escape(ai['mode'])}</strong><br>
            INTENSITY SCORE: <code>{ai['intensity_score']}</code><br>
            <pre>Context Snapshot: {html.escape(json.dumps(ai['context_snapshot'], indent=2))}</pre>
        </div>"""
        html_content += '</div>'

    # Steganography
    steg = data.get('stegano_status', '')
    if steg:
        html_content += '<div class="card"><h2>Steganographic Channel: Covert Smuggling</h2>'
        html_content += f"""
        <div class="finding info">
            <span class="severity-badge INFO">STEGANO</span>
            <strong>STATUS: {html.escape(steg)}</strong><br>
            DECODED C2 INSTRUCTION: <code>{html.escape(data.get('stegano_decoded_sample', 'None'))}</code>
        </div>"""
        html_content += '</div>'

    # Polyglot
    polyglot = data.get('polyglot_discovery', '')
    if polyglot:
        html_content += '<div class="card"><h2>Polyglot Delivery: Advanced Evasion Templates</h2>'
        html_content += f"""
        <div class="finding info">
            <span class="severity-badge INFO">POLYGLOT</span>
            <strong>{html.escape(polyglot)}</strong>
        </div>"""
        html_content += '</div>'

    # Memory
    memory = data.get('memory_indicators', {})
    if memory:
        html_content += '<div class="card"><h2>Stealth Analytics: RAM-Resident Indicators</h2>'
        for ip, indicators in memory.items():
            for ind in indicators:
                html_content += f"""
                <div class="finding high">
                    <span class="severity-badge CRITICAL">MEMORY-RESIDENT</span>
                    <strong>{html.escape(ind['indicator'])}</strong> (PID: {html.escape(ind['pid'])})
                    <pre>{html.escape(ind['details'])}</pre>
                </div>"""
        html_content += '</div>'

    # Fuzzing
    fuzzing = data.get('fuzzing_findings', {})
    if fuzzing:
        html_content += '<div class="card"><h2>Automated Surface Fuzzing Results</h2>'
        for ip, findings in fuzzing.items():
            for f in findings:
                rem = get_remediation(f['finding'])
                html_content += f"""
                <div class="finding">
                    <span class="severity-badge {rem['severity']}">{rem['severity']}</span>
                    <strong>{html.escape(f['finding'])}</strong><br>
                    URL: {html.escape(f['url'])} | PAYLOAD: <code>{html.escape(f['payload'])}</code>
                    <div class="remediation"><strong>REMEDIATION:</strong> {html.escape(rem['remediation'])}</div>
                </div>"""
        html_content += '</div>'

    # Context
    triggers = data.get('triggered_operations', {})
    if triggers:
        html_content += '<div class="card"><h2>Autonomous Logic: Context Triggers</h2>'
        for ip, t_list in triggers.items():
            for t in t_list:
                html_content += f"""
                <div class="finding info">
                    <span class="severity-badge INFO">AUTONOMOUS</span>
                    <strong>Rule: {html.escape(t['rule'])}</strong> (Status: {html.escape(t['status'])})
                </div>"""
        html_content += '</div>'

    # Lateral Movement & Attack Path
    lateral = data.get('lateral_movement_paths', {})
    if lateral:
        html_content += '<div class="card"><h2>Attack Path & Lateral Movement Visualization</h2>'
        html_content += '<div style="background: rgba(0,255,65,0.05); padding: 20px; border-radius: 8px;">'
        for jump_box, targets in lateral.items():
            html_content += f"""
            <div style="margin-bottom: 15px;">
                <span style="color: var(--accent);">[ENTRY]</span> {html.escape(jump_box)}
                <span style="color: var(--accent);">──►</span>
                <span style="color: var(--info);">{html.escape(', '.join(targets))}</span>
            </div>"""
        html_content += '</div></div>'

    # Security Software
    av = data.get('security_software', {})
    if av:
        html_content += '<div class="card"><h2>EDR/AV & Security Software Detection</h2>'
        for ip, software in av.items():
            html_content += f"<h3>Host: {html.escape(ip)}</h3><ul>"
            for s in software:
                html_content += f"<li><strong>{html.escape(s)}</strong></li>"
            html_content += "</ul></div>"

    # Supply Chain
    supply = data.get('supply_chain_vulns', {})
    if supply:
        html_content += '<div class="card"><h2>Supply Chain & Dependency Analysis</h2>'
        for ip, vulns in supply.items():
            for v in vulns:
                html_content += f"""
                <div class="finding high">
                    <span class="severity-badge HIGH">VULNERABLE_PKG</span>
                    <strong>{html.escape(v['package'])} ({html.escape(v['match'])})</strong> on {html.escape(ip)}<br>
                    {html.escape(v['finding'])}
                </div>"""
        html_content += '</div>'

    # Kernel Risks
    ker = data.get('escalation_risks', {})
    if ker:
        html_content += '<div class="card"><h2>Privilege Escalation: Kernel & Config Risks</h2>'
        for ip, risks in ker.items():
            for r in risks:
                html_content += f"""
                <div class="finding high">
                    <span class="severity-badge {r['severity']}">{html.escape(r['type'])}</span>
                    <strong>{html.escape(r['finding'])}</strong> on {html.escape(ip)}<br>
                    <pre>{html.escape(r.get('details', ''))}</pre>
                </div>"""
        html_content += '</div>'

    # Comp hosts
    comp = data.get('compromised_hosts', {})
    if comp:
        html_content += '<div class="card"><h2>Access Control: Compromised Host Summary</h2>'
        for ip, creds in comp.items():
            for c in creds:
                html_content += f"""
                <div class="finding high">
                    <span class="severity-badge CRITICAL">ACCESS GAINED</span>
                    <strong>{html.escape(ip)} - {html.escape(c['service'].upper())}</strong><br>
                    IDENTITY: <code>{html.escape(c['username'])}:{html.escape(c['password'])}</code>
                </div>"""
        html_content += '</div>'

    html_content += """
            <div style="text-align: center; margin-top: 50px; color: var(--text-secondary); font-size: 0.8em;">
                OMNISTRIKE APEX ELITE COMMAND CENTER • [STATUS: ACTIVE]
            </div>
        </div>
    </body>
    </html>
    """

    with open(output_file, 'w') as f:
        f.write(html_content)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 generate_report.py results.json report.html")
        sys.exit(1)

    with open(sys.argv[1], 'r') as f:
        data = json.load(f)

    generate_html(data, sys.argv[2])
    print(f"[*] OmniStrike Apex Dashboard generated: {sys.argv[2]}")
