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
    "Potential Insecure Deserialization": {"remediation": "Audit object serialization endpoints. Use safe serialization libraries.", "severity": "HIGH"},
    "Potential XML External Entity (XXE)": {"remediation": "Disable external entity processing in XML parsers.", "severity": "HIGH"},
    "Potential Server-Side Request Forgery (SSRF)": {"remediation": "Implement strict whitelisting for outbound requests.", "severity": "MEDIUM"},
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
            <div style="font-size: 0.8em; color: var(--text-secondary); margin-bottom: 10px;">Sovereign Edition v8.0</div>
            <div style="font-size: 0.8em; color: var(--text-secondary); margin-bottom: 30px;">Digital Shadow Intelligence</div>
            <div style="margin-bottom: 10px;">• TARGET: {target}</div>
            <div style="margin-bottom: 10px;">• UPTIME: 100%</div>
            <div style="margin-bottom: 10px;">• NODES: {len(data.get('compromised_hosts', {}))} active</div>
            <div style="margin-bottom: 10px;">• AI: MULTI-CONSENSUS</div>
            <div style="margin-bottom: 10px;">• STEALTH: ACTIVE</div>
        </div>
        <div class="main-content">
            <h1>SOVEREIGN COMMAND: OPERATION {target.upper()}</h1>

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

    # AI Consensus
    consensus = data.get('ai_consensus', {})
    if consensus:
        html_content += '<div class="card"><h2>Consensus Intelligence: Multi-Model AI Analysis</h2>'
        html_content += f"""
        <div class="finding info">
            <span class="severity-badge INFO">AI_CONSENSUS</span>
            <strong>{html.escape(consensus['summary'])}</strong><br>
            <pre>Provider Responses: {html.escape(json.dumps(consensus['individual_responses'], indent=2))}</pre>
        </div>"""
        html_content += '</div>'

    # Stealth Orchestration
    stealth = data.get('stealth_strategy', {})
    if stealth:
        html_content += '<div class="card"><h2>Stealth Orchestration: Operational Profile</h2>'
        html_content += f"""
        <div class="finding info">
            <span class="severity-badge INFO">STEALTH_PROFILE</span>
            <strong>PROFILE: {html.escape(stealth['operational_profile'])}</strong><br>
            STRATEGIC ADVICE: <em>{html.escape(stealth['strategic_advice'])}</em><br>
            <pre>Evasion Capabilities: {html.escape(json.dumps(stealth['evasion_capabilities'], indent=2))}</pre>
        </div>"""
        html_content += '</div>'

    # Exploit Intelligence
    intel = data.get('exploit_intelligence', [])
    if intel:
        html_content += '<div class="card"><h2>Offensive Brain: Exploit Intelligence</h2>'
        for path in intel:
            html_content += f"""
            <div class="finding">
                <span class="severity-badge INFO">PRIORITY_{path['priority']}</span>
                <strong>{html.escape(path['vector'])} on {html.escape(path['target'])}</strong><br>
                RISK SCORE: <code>{path['risk_score']}</code> | ACTION: <strong>{path['action']}</strong>
            </div>"""
        html_content += '</div>'

    # Attack Lab
    attack_lab = data.get('payload_recommendations', [])
    if attack_lab:
        html_content += '<div class="card"><h2>Attack Vector Lab: Optimal Payload Recommendations</h2>'
        for r in attack_lab:
            html_content += f"""
            <div class="finding info">
                <span class="severity-badge INFO">LAB_READY</span>
                <strong>Target: {html.escape(r['target'])}</strong><br>
                For {html.escape(r['vuln_type'])}, use category: <code>{html.escape(r['recommended_payload_category'].upper())}</code>
            </div>"""
        html_content += '</div>'

    # Deep Vulnerabilities
    deep_vulns = data.get('deep_vulnerabilities', [])
    if deep_vulns:
        html_content += '<div class="card"><h2>Vulnerability Matrix: Sophisticated Findings</h2>'
        for v in deep_vulns:
            rem = get_remediation(v['type'])
            html_content += f"""
            <div class="finding">
                <span class="severity-badge {v['severity']}">{v['severity']}</span>
                <strong>{html.escape(v['type'])}</strong> on {html.escape(v['ip'])}:<code>{v['port']}</code><br>
                Confidence: {v['confidence']*100:.0f}%
                <div class="remediation"><strong>Remediation:</strong> {html.escape(rem['remediation'])}</div>
            </div>"""
        html_content += '</div>'

    # Zero-Click Surfaces
    zeroclick = data.get('zeroclick_surfaces', {})
    if zeroclick:
        html_content += '<div class="card"><h2>Zero-Click Attack Surface Audit</h2>'
        for ip, findings in zeroclick.items():
            for f in findings:
                html_content += f"""
                <div class="finding high">
                    <span class="severity-badge HIGH">ZERO_CLICK</span>
                    <strong>{html.escape(f['service'])}</strong> on {html.escape(ip)}:<code>{f['port']}</code><br>
                    Potential for unauthorized remote interaction.
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

    # Harvested Secrets
    secrets = data.get('harvested_secrets', {})
    if secrets:
        html_content += '<div class="card"><h2>Exfiltration Intel: Harvested Secrets & Keys</h2>'
        for sid, findings in secrets.items():
            html_content += f"<h3>Session {sid} Findings</h3>"
            for f in findings:
                html_content += f"""
                <div class="finding high">
                    <span class="severity-badge CRITICAL">{html.escape(f['type'])}</span>
                    <strong>Extracted Value:</strong> <code>{html.escape(str(f['match']))}</code>
                </div>"""
        html_content += '</div>'

    # Backdoor Deployments
    backdoors = data.get('backdoor_deployments', {})
    if backdoors:
        html_content += '<div class="card"><h2>Persistence Strategy: Morphing Backdoors</h2>'
        for sid, path in backdoors.items():
            html_content += f"""
            <div class="finding high">
                <span class="severity-badge CRITICAL">MORPHED_PERSISTENCE</span>
                <strong>Session {sid} Control Path: <code>{html.escape(path)}</code></strong><br>
                STATUS: Active | LOGIC: Polymorphic Bash | TRIGGERS: Cron, Bashrc
            </div>"""
        html_content += '</div>'

    # Advanced Persistence
    adv_pers = data.get('advanced_persistence_status', '')
    if adv_pers:
        html_content += '<div class="card"><h2>Sovereign Persistence: Advanced LotL Techniques</h2>'
        html_content += f"""
        <div class="finding high">
            <span class="severity-badge CRITICAL">LOTL_PERSISTENCE</span>
            <strong>Status: {html.escape(adv_pers)}</strong><br>
            Techniques: Systemd Generators, COM Hijacking, WMI Consumers.
        </div>"""
        html_content += '</div>'

    # Session Intelligence
    sessions = data.get('session_intelligence', {})
    if sessions:
        html_content += '<div class="card"><h2>Sovereign Asset Intel: Deep-Dive Session Profiles</h2>'
        for sid, info in sessions.items():
            html_content += f"""
            <div class="finding info">
                <span class="severity-badge INFO">SESSION_{sid}</span>
                <strong>Identity: {html.escape(str(info.get('identity', 'Unknown')))}</strong><br>
                KERNEL: <code>{html.escape(str(info.get('kernel', 'N/A')))}</code><br>
                UPTIME: <em>{html.escape(str(info.get('uptime', 'N/A')))}</em><br>
                SECURITY: <span style="color: var(--warning);">{html.escape(str(info.get('security_indicators', 'None')))}</span>
                <pre>Interfaces: {html.escape(str(info.get('interfaces', [])))}</pre>
            </div>"""
        html_content += '</div>'

    # Decoy Intelligence
    decoys = data.get('decoy_intelligence', [])
    if decoys:
        html_content += '<div class="card"><h2>Decoy Intelligence: Threat Trap Detection</h2>'
        for f in decoys:
            html_content += f"""
            <div class="finding">
                <span class="severity-badge HIGH">DECOY_DETECTED</span>
                <strong>{html.escape(f['type'])}</strong>: <code>{html.escape(f['indicator'])}</code><br>
                Confidence: {html.escape(str(f['confidence']))} | RISK: <strong>{html.escape(f['risk'])}</strong>
            </div>"""
        html_content += '</div>'

    # Identity Shadow
    ident = data.get('identity_shadow_audit', [])
    if ident:
        html_content += '<div class="card"><h2>Identity Shadow Matrix: Ghost Tokens & Shadow Credentials</h2>'
        for f in ident:
            html_content += f"""
            <div class="finding">
                <span class="severity-badge CRITICAL">{html.escape(f['type'])}</span>
                <strong>Target: {html.escape(f.get('target_account', f.get('target_resource', 'Global')))}</strong><br>
                {html.escape(f['vulnerability'])} | RISK: <em>{html.escape(f['risk'])}</em>
            </div>"""
        html_content += '</div>'

    # Supply Chain Pulse
    pulse = data.get('supply_chain_pulse', [])
    if pulse:
        html_content += '<div class="card"><h2>Supply Chain Pulse: Dependency Confusion Audit</h2>'
        for f in pulse:
            html_content += f"""
            <div class="finding high">
                <span class="severity-badge CRITICAL">{html.escape(f['vulnerability'])}</span>
                <strong>Package: <code>{html.escape(f['package'])}</code></strong><br>
                Status: {html.escape(f['status'])} | {html.escape(f['risk'])}
            </div>"""
        html_content += '</div>'

    # FaaS Audit
    faas = data.get('faas_audit_results', [])
    if faas:
        html_content += '<div class="card"><h2>Serverless Surface Audit (FaaS)</h2>'
        for f in faas:
            html_content += f"""
            <div class="finding">
                <span class="severity-badge CRITICAL">{html.escape(f['type'])}</span>
                <strong>Resource: {html.escape(f['resource'])}</strong><br>
                {html.escape(f['finding'])} | RISK: <em>{html.escape(f['risk'])}</em>
            </div>"""
        html_content += '</div>'

    # EDR Blindspots
    edr = data.get('edr_blindspots', [])
    if edr:
        html_content += '<div class="card"><h2>EDR Blindspot Audit & Bypass Trajectories</h2>'
        for f in edr:
            html_content += f"""
            <div class="finding">
                <span class="severity-badge INFO">{html.escape(f['type'])}</span>
                <strong>{html.escape(f.get('api', f.get('finding', 'General')))}</strong><br>
                {html.escape(f.get('recommendation', ''))}
                <pre>{html.escape(str(f.get('details', '')))}</pre>
            </div>"""
        html_content += '</div>'

    # LLM Injection
    llm = data.get('llm_injection_findings', [])
    if llm:
        html_content += '<div class="card"><h2>AI/LLM Injection & Exfiltration Audit</h2>'
        for f in llm:
            html_content += f"""
            <div class="finding high">
                <span class="severity-badge CRITICAL">{html.escape(f['type'])}</span>
                <strong>Endpoint: {html.escape(f['endpoint'])}</strong><br>
                PAYLOAD: <code>{html.escape(f['payload'])}</code> | RISK: <em>{html.escape(f['risk'])}</em>
            </div>"""
        html_content += '</div>'

    # Cloud Graph
    c_graph = data.get('cloud_graph_intelligence', [])
    if c_graph:
        html_content += '<div class="card"><h2>Cloud IAM Graph Intelligence: Multihop PrivEsc</h2>'
        for f in c_graph:
            html_content += f"""
            <div class="finding">
                <span class="severity-badge CRITICAL">{html.escape(f['type'])}</span>
                <strong>Path Identified:</strong><br>
                <code>{html.escape(f['path'])}</code><br>
                RISK: <em>{html.escape(f['risk'])}</em>
            </div>"""
        html_content += '</div>'

    # eBPF Phantom
    ebpf = data.get('ebpf_phantom_status', [])
    if ebpf:
        html_content += '<div class="card"><h2>EBpf Phantom: Invisible Kernel Persistence</h2>'
        for f in ebpf:
            html_content += f"""
            <div class="finding high">
                <span class="severity-badge CRITICAL">{html.escape(f['type'])}</span>
                <strong>Hook: {html.escape(f['hook_point'] if 'hook_point' in f else f['interface'])}</strong><br>
                {html.escape(f['purpose'])} | Status: <strong>{html.escape(f['status'])}</strong>
            </div>"""
        html_content += '</div>'

    # Exfil Diversion
    exfil = data.get('exfil_diversion_status', [])
    if exfil:
        html_content += '<div class="card"><h2>Covert Exfiltration & Protocol Diversion</h2>'
        for f in exfil:
            html_content += f"""
            <div class="finding info">
                <span class="severity-badge INFO">{html.escape(f['type'])}</span>
                <strong>Protocol: {html.escape(f['protocol'])}</strong><br>
                Activity detected in simulated channel.
            </div>"""
        html_content += '</div>'

    # Swarm Results
    swarm = data.get('swarm_results', {})
    if swarm:
        html_content += '<div class="card"><h2>Swarm Coordination: Distributed Command Results</h2>'
        for sid, res in swarm.items():
            html_content += f"""
            <div class="finding info">
                <span class="severity-badge INFO">SWARM_NODE_{sid}</span>
                <strong>Result from Session {sid}:</strong><br>
                <pre>{html.escape(str(res))}</pre>
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
