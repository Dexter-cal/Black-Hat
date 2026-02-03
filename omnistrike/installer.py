import subprocess
import sys
import shutil
import logging

class DependencyInstaller:
    """
    Automatically verifies and installs missing Python and system dependencies.
    """
    PYTHON_DEPS = [
        'requests', 'beautifulsoup4', 'Pillow', 'python-docx',
        'scapy', 'dnspython', 'phonenumbers', 'aiohttp',
        'aiohttp-socks', 'python-socks', 'asyncssh', 'pyyaml', 'astor'
    ]

    SYSTEM_DEPS = [
        'nmap', 'masscan', 'nikto', 'aircrack-ng', 'john',
        'hashcat', 'sqlmap', 'gobuster', 'ffuf', 'amass',
        'subfinder', 'nuclei'
    ]

    @staticmethod
    def check_and_install():
        print("🔧 [OmniStrike] Verifying system dependencies...")

        # 1. Check Python Packages
        missing_python = []
        for pkg in DependencyInstaller.PYTHON_DEPS:
            try:
                # Handle package names that differ from import names
                import_name = pkg.replace('-', '_')
                __import__(import_name)
            except ImportError:
                missing_python.append(pkg)

        if missing_python:
            print(f"[*] Installing missing Python packages: {', '.join(missing_python)}")
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + missing_python)
            except Exception as e:
                print(f"[!] Python dependency installation failed: {e}")

        # 2. Check System Tools
        missing_system = []
        for tool in DependencyInstaller.SYSTEM_DEPS:
            if not shutil.which(tool.split('-')[0]):
                missing_system.append(tool)

        if missing_system:
            print(f"⚠️  System tools missing: {', '.join(missing_system)}")
            print("[*] Recommendation: Install missing tools via your package manager.")
            if sys.platform == 'linux':
                print(f"    sudo apt install {' '.join(missing_system)}")
            elif sys.platform == 'darwin':
                print(f"    brew install {' '.join(missing_system)}")

        print("✅ [OmniStrike] Dependency check complete.")
