import json
import sys
import html

def generate_html(data, output_file):
    target = html.escape(str(data.get('target', 'Unknown')))
    html_content = f"""
    <html>
    <head>
        <title>SecAudit Report - {target}</title>
        <style>
            body {{ font-family: sans-serif; background-color: #f4f4f4; color: #333; }}
            .container {{ width: 80%; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            h1, h2 {{ color: #0056b3; }}
            .section {{ margin-bottom: 20px; border-bottom: 1px solid #ddd; padding-bottom: 10px; }}
            .finding {{ padding: 10px; margin: 5px 0; border-radius: 4px; }}
            .high {{ background-color: #ffe6e6; border-left: 5px solid #d9534f; }}
            .info {{ background-color: #e6f3ff; border-left: 5px solid #5bc0de; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>SecAudit Security Audit Report</h1>
            <div class="section">
                <h2>General Information</h2>
                <p><strong>Target:</strong> {target}</p>
            </div>
    """

    # Subdomains
    subdomains = data.get('subdomains', {})
    if subdomains:
        html_content += '<div class="section"><h2>Discovered Subdomains</h2><ul>'
        for sub, ips in subdomains.items():
            sub_escaped = html.escape(sub)
            ips_escaped = html.escape(', '.join(ips))
            html_content += f"<li><strong>{sub_escaped}</strong>: {ips_escaped}</li>"
        html_content += '</ul></div>'

    # Open Ports
    open_ports = data.get('open_ports', {})
    fingerprints = data.get('fingerprints', {})
    if open_ports:
        html_content += '<div class="section"><h2>Open Ports & Services</h2><table><tr><th>IP</th><th>OS Fingerprint</th><th>Port</th><th>Banner</th></tr>'
        for ip, ports in open_ports.items():
            for port, banner in ports.items():
                ip_escaped = html.escape(str(ip))
                fp_escaped = html.escape(str(fingerprints.get(ip, "Unknown")))
                port_escaped = html.escape(str(port))
                banner_escaped = html.escape(str(banner or 'N/A'))
                html_content += f"<tr><td>{ip_escaped}</td><td>{fp_escaped}</td><td>{port_escaped}</td><td>{banner_escaped}</td></tr>"
        html_content += '</table></div>'

    # Exploit Findings
    exploits = data.get('exploit_findings', {})
    if exploits:
        html_content += '<div class="section"><h2>Exploitable Misconfigurations</h2>'
        for ip, findings in exploits.items():
            for f in findings:
                finding_escaped = html.escape(f['finding'])
                url_escaped = html.escape(f['url'])
                severity_escaped = html.escape(f['severity'])
                html_content += f"""
                <div class="finding high">
                    <strong>{finding_escaped}</strong><br>
                    URL: <a href="{url_escaped}">{url_escaped}</a> (Severity: {severity_escaped})
                </div>
                """
        html_content += '</div>'

    # Credentials
    creds = data.get('credentials_found', {})
    if creds:
        html_content += '<div class="section"><h2>Weak Credentials Found</h2>'
        for ip, c_list in creds.items():
            for c in c_list:
                service_escaped = html.escape(c['service'])
                username_escaped = html.escape(c['username'])
                password_escaped = html.escape(c['password'])
                html_content += f"""
                <div class="finding high">
                    <strong>Service: {service_escaped}</strong><br>
                    Credentials: <code>{username_escaped}:{password_escaped}</code>
                </div>
                """
        html_content += '</div>'

    # Vulnerability Verification Results
    verification = data.get('verification_results', {})
    if verification:
        html_content += '<div class="section"><h2>Vulnerability Verification Results</h2>'
        for r in verification:
            verifier_escaped = html.escape(r['verifier'])
            target_escaped = html.escape(r['target'])
            finding_escaped = html.escape(r['finding'])
            severity_escaped = html.escape(r['severity'])
            html_content += f"""
            <div class="finding high">
                <strong>{verifier_escaped} on {target_escaped}</strong><br>
                Confirmed: {finding_escaped} (Severity: {severity_escaped})
            </div>
            """
        html_content += '</div>'

    # System Audit Results
    system_audit = data.get('persistence_findings', {}) # Still using same key for compatibility or update it
    if system_audit:
        html_content += '<div class="section"><h2>System Audit Findings</h2>'
        for ip, findings in system_audit.items():
            for f in findings:
                check_escaped = html.escape(f['check'])
                output_escaped = html.escape(f['output_snippet'])
                html_content += f"""
                <div class="finding high">
                    <strong>{check_escaped}</strong><br>
                    <pre>{output_escaped}</pre>
                </div>
                """
        html_content += '</div>'

    html_content += """
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
    print(f"[*] HTML report generated: {sys.argv[2]}")
