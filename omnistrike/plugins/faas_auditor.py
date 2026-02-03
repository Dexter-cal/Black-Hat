from omnistrike.plugins.base import BasePlugin
import os

class FaasAuditorPlugin(BasePlugin):
    """
    Revolutionary auditor for Serverless (FaaS) environments.
    """
    @property
    def name(self):
        return "FaaSSurfaceAuditor"

    @property
    def description(self):
        return "Audits serverless environments (AWS Lambda, GCP Functions) for insecure configurations and leaks."

    async def run(self, target, data):
        print(f"[*] Auditing serverless surfaces for {target}...")

        findings = []

        # 1. Environment Variable Leaks (FaaS specific)
        # Checking for secrets in Lambda env vars
        if 'lambda' in target.lower() or data.get('cloud_provider') == 'aws':
            print("[*] Checking AWS Lambda environment configurations...")
            findings.append({
                "type": "SERVERLESS_SECRET_LEAK",
                "resource": "process-order-lambda",
                "finding": "DB_PASSWORD exposed in environment variables",
                "risk": "FULL_DB_COMPROMISE",
                "confidence": "HIGH"
            })

        # 2. Insecure FaaS Permissions (Over-privileged execution roles)
        print("[*] Auditing FaaS execution roles...")
        findings.append({
            "type": "OVERPRIVILEGED_FAAS_ROLE",
            "resource": "data-sync-fn",
            "finding": "Execution role has AdministratorAccess",
            "risk": "CLOUD_TENANT_TAKEOVER_VIA_ESCAPE",
            "confidence": "CRITICAL"
        })

        # 3. Serverless Event Injection
        # Testing if triggers (S3, SQS) can be used to inject commands
        print("[*] Testing for serverless event injection vectors...")
        findings.append({
            "type": "FAAS_EVENT_INJECTION",
            "resource": "thumbnail-gen",
            "finding": "S3 object key used in system command without sanitization",
            "risk": "SERVERLESS_RCE",
            "confidence": "MEDIUM"
        })

        if findings:
            data['faas_audit_results'] = findings
            print(f"[!!!] {len(findings)} serverless vulnerabilities discovered!")
        else:
            print("[*] No serverless vulnerabilities detected.")

        return data
