import json
import sys
import html

# Remediation Intelligence Database
REMEDIATION_DB = {
    "Potential SQL Injection": {
        "remediation": "Use prepared statements and parameterized queries. Implement strict input validation.",
        "severity": "CRITICAL"
    },
    "Potential Cross-Site Scripting (XSS)": {
        "remediation": "Implement output encoding for all user-supplied data. Use Content Security Policy (CSP).",
        "severity": "HIGH"
    },
    "Potential Directory Traversal": {
        "remediation": "Validate and sanitize all file paths. Use indirect references for file access.",
        "severity": "HIGH"
    },
    "Potential Command Injection": {
        "remediation": "Avoid executing system commands with user input. Use safe APIs or strict whitelisting.",
        "severity": "CRITICAL"
    },
    "Exposed Git repository confirmed": {
        "remediation": "Restrict access to the .git directory or remove it from the web server root.",
        "severity": "HIGH"
    },
    "Deprecated TLS version detected": {
        "remediation": "Disable TLS 1.0 and 1.1. Upgrade to TLS 1.2 or 1.3.",
        "severity": "MEDIUM"
    },
    "Weak cipher suite detected": {
        "remediation": "Disable weak ciphers (e.g., 3DES, RC4). Prioritize AEAD ciphers like AES-GCM.",
        "severity": "MEDIUM"
    },
    "Sensitive environment variables exposed": {
        "remediation": "Ensure .env files are not accessible via the web server. Move secrets to a secure vault.",
        "severity": "CRITICAL"
    },
    "Potential subdomain takeover": {
        "remediation": "Remove dangling CNAME records in your DNS configuration for services no longer in use.",
        "severity": "CRITICAL"
    },
    "PUBLIC Cloud Storage": {
        "remediation": "Update bucket policies and IAM roles to restrict public access. Enable S3 Block Public Access.",
        "severity": "HIGH"
    },
    "Data Leakage": {
        "remediation": "Remove sensitive information from public-facing code, banners, and files. Rotate compromised keys.",
        "severity": "HIGH"
    }
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
        <title>OmniStrike Apex Report - {target}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f0f2f5; color: #1c1e21; line-height: 1.6; }}
            .container {{ width: 85%; max-width: 1200px; margin: 40px auto; background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }}
            h1 {{ color: #0056b3; border-bottom: 3px solid #0056b3; padding-bottom: 10px; margin-bottom: 30px; }}
            h2 {{ color: #333; margin-top: 30px; border-left: 5px solid #0056b3; padding-left: 15px; }}
            .section {{ margin-bottom: 40px; }}
            .finding {{ padding: 20px; margin: 15px 0; border-radius: 8px; border: 1px solid #ddd; position: relative; }}
            .severity-badge {{ position: absolute; top: 15px; right: 20px; padding: 5px 12px; border-radius: 20px; font-weight: bold; font-size: 0.8em; text-transform: uppercase; }}
            .CRITICAL {{ background-color: #721c24; color: #fff; }}
            .HIGH {{ background-color: #dc3545; color: #fff; }}
            .MEDIUM {{ background-color: #ffc107; color: #212529; }}
            .INFO {{ background-color: #17a2b8; color: #fff; }}
            .remediation {{ margin-top: 15px; padding: 15px; background-color: #e9ecef; border-radius: 4px; font-style: italic; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid #eee; }}
            th {{ background-color: #f8f9fa; color: #495057; }}
            pre {{ background-color: #212529; color: #f8f9fa; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 0.9em; }}
            code {{ background-color: #f1f3f5; padding: 2px 4px; border-radius: 4px; font-family: monospace; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>OmniStrike Apex - Security Audit Report</h1>
            <div class="section">
                <h2>General Information</h2>
                <p><strong>Target:</strong> {target}</p>
                <p><strong>Status:</strong> Audit Completed Successfully</p>
            </div>
    """

    # Subdomains
    subdomains = data.get('subdomains', {})
    if subdomains:
        html_content += '<div class="section"><h2>Discovered Subdomains</h2><ul>'
        for sub, ips in subdomains.items():
            html_content += f"<li><strong>{html.escape(sub)}</strong>: {html.escape(', '.join(ips))}</li>"
        html_content += '</ul></div>'

    # Open Ports
    open_ports = data.get('open_ports', {})
    fingerprints = data.get('fingerprints', {})
    if open_ports:
        html_content += '<div class="section"><h2>Network Discovery</h2><table><tr><th>IP Address</th><th>OS Fingerprint</th><th>Port</th><th>Service Banner</th></tr>'
        for ip, ports in open_ports.items():
            for port, banner in ports.items():
                html_content += f"""
                <tr>
                    <td>{html.escape(str(ip))}</td>
                    <td>{html.escape(str(fingerprints.get(ip, 'Unknown')))}</td>
                    <td><code>{html.escape(str(port))}</code></td>
                    <td><code>{html.escape(str(banner or 'N/A'))}</code></td>
                </tr>"""
        html_content += '</table></div>'

    # Exploit Scanner Findings
    exploits = data.get('exploit_findings', {})
    if exploits:
        html_content += '<div class="section"><h2>Exploitable Misconfigurations</h2>'
        for ip, findings in exploits.items():
            for f in findings:
                rem = get_remediation(f['finding'])
                html_content += f"""
                <div class="finding">
                    <span class="severity-badge {rem['severity']}">{rem['severity']}</span>
                    <strong>{html.escape(f['finding'])}</strong><br>
                    URL: <a href="{html.escape(f['url'])}">{html.escape(f['url'])}</a>
                    <div class="remediation"><strong>Remediation:</strong> {html.escape(rem['remediation'])}</div>
                </div>"""
        html_content += '</div>'

    # Web Fuzzing Results
    fuzzing = data.get('fuzzing_findings', {})
    if fuzzing:
        html_content += '<div class="section"><h2>Automated Web Vulnerability Fuzzing</h2>'
        for ip, findings in fuzzing.items():
            for f in findings:
                rem = get_remediation(f['finding'])
                html_content += f"""
                <div class="finding">
                    <span class="severity-badge {rem['severity']}">{rem['severity']}</span>
                    <strong>{html.escape(f['finding'])}</strong><br>
                    URL: {html.escape(f['url'])} | Payload: <code>{html.escape(f['payload'])}</code>
                    <div class="remediation"><strong>Remediation:</strong> {html.escape(rem['remediation'])}</div>
                </div>"""
        html_content += '</div>'

    # Protocol Audit
    protocol = data.get('protocol_audit', {})
    if protocol:
        html_content += '<div class="section"><h2>Cryptographic Protocol Audit</h2>'
        for ip, findings in protocol.items():
            for f in findings:
                rem = get_remediation(f['finding'])
                html_content += f"""
                <div class="finding">
                    <span class="severity-badge {f['severity']}">{f['severity']}</span>
                    <strong>Port {html.escape(str(f['port']))}: {html.escape(f['finding'])}</strong>
                    <div class="remediation"><strong>Remediation:</strong> {html.escape(rem['remediation'])}</div>
                </div>"""
        html_content += '</div>'

    # System Audit Results
    system_audit = data.get('persistence_findings', {})
    if system_audit:
        html_content += '<div class="section"><h2>Host Security Posture Audit</h2>'
        for ip, findings in system_audit.items():
            for f in findings:
                html_content += f"""
                <div class="finding">
                    <span class="severity-badge INFO">INFO</span>
                    <strong>{html.escape(f['check'])}</strong><br>
                    <pre>{html.escape(f['output_snippet'])}</pre>
                </div>"""
        html_content += '</div>'

    # Cloud Storage
    cloud = data.get('cloud_storage', [])
    if cloud:
        html_content += '<div class="section"><h2>Cloud Storage Audit</h2>'
        for c in cloud:
            rem = get_remediation(f"{c['status']} Cloud Storage")
            html_content += f"""
            <div class="finding">
                <span class="severity-badge {rem['severity']}">{rem['severity']}</span>
                <strong>{html.escape(c['status'])}: {html.escape(c['url'])}</strong>
                <div class="remediation"><strong>Remediation:</strong> {html.escape(rem['remediation'])}</div>
            </div>"""
        html_content += '</div>'

    # Subdomain Takeover
    takeovers = data.get('subdomain_takeovers', [])
    if takeovers:
        html_content += '<div class="section"><h2>Subdomain Takeover Analysis</h2>'
        for t in takeovers:
            rem = get_remediation("Potential subdomain takeover")
            html_content += f"""
            <div class="finding">
                <span class="severity-badge {t['severity']}">{t['severity']}</span>
                <strong>{html.escape(t['subdomain'])} -> {html.escape(t['service'])}</strong>
                <div class="remediation"><strong>Remediation:</strong> {html.escape(rem['remediation'])}</div>
            </div>"""
        html_content += '</div>'

    # Data Leakage
    leaks = data.get('data_leaks', [])
    if leaks:
        html_content += '<div class="section"><h2>Data Leakage Analysis</h2>'
        for l in leaks:
            rem = get_remediation("Data Leakage")
            html_content += f"""
            <div class="finding">
                <span class="severity-badge {l['severity']}">{l['severity']}</span>
                <strong>[{html.escape(l['type'])}] {html.escape(l['source'])}</strong>
                <div class="remediation"><strong>Remediation:</strong> {html.escape(rem['remediation'])}</div>
            </div>"""
        html_content += '</div>'

    # Security Baseline
    baseline = data.get('security_baseline', {})
    if baseline:
        html_content += '<div class="section"><h2>Security Baseline Audit (Linux)</h2>'
        for ip, findings in baseline.items():
            html_content += f"<h3>Host: {html.escape(ip)}</h3>"
            for f in findings:
                html_content += f"""
                <div class="finding">
                    <strong>{html.escape(f['check'])}</strong><br>
                    <pre>{html.escape(f['output'])}</pre>
                </div>"""
        html_content += '</div>'

    # Adversary Simulation
    adv_sim = data.get('adversary_simulation', {})
    if adv_sim:
        html_content += '<div class="section"><h2>Adversary Simulation Log (TTP Execution)</h2>'
        for ip, findings in adv_sim.items():
            for f in findings:
                html_content += f"""
                <div class="finding">
                    <span class="severity-badge INFO">SIMULATION</span>
                    <strong>{html.escape(f['technique'])}</strong> (Status: {html.escape(f['status'])})<br>
                    <pre>{html.escape(f['output_preview'])}</pre>
                </div>"""
        html_content += '</div>'

    html_content += """
            <div style="text-align: center; margin-top: 50px; color: #777; font-size: 0.9em;">
                Report generated by OmniStrike Apex Elite Framework.
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
    print(f"[*] Professional Apex report generated: {sys.argv[2]}")
