import abc
import os
import platform

class BaseAdapter(abc.ABC):
    @abc.abstractmethod
    def get_system_info(self):
        pass

    @abc.abstractmethod
    def hide_process(self):
        pass

    @abc.abstractmethod
    def get_context_metrics(self):
        pass

class LinuxAdapter(BaseAdapter):
    def get_system_info(self):
        return {
            "os": "Linux",
            "kernel": platform.release(),
            "distro": platform.node(),
            "arch": platform.machine()
        }

    def hide_process(self):
        # Conceptual: In a real red team tool, this might involve LD_PRELOAD
        # or other techniques. Here we just set a deceptive name.
        print("[*] Adapter: Cloaking process as 'kworker/u2:1'...")
        # In python, we can use setproctitle if installed
        try:
            import setproctitle
            setproctitle.setproctitle("kworker/u2:1")
        except:
            pass

    def get_context_metrics(self):
        # Functional metrics collection
        load = os.getloadavg() if hasattr(os, 'getloadavg') else (0,0,0)
        return {
            "cpu_load": load[0],
            "active_users": len(os.popen("who").readlines()),
            "battery": self._get_battery()
        }

    def _get_battery(self):
        try:
            with open("/sys/class/power_supply/BAT0/capacity", "r") as f:
                return int(f.read().strip())
        except:
            return 100

class AndroidAdapter(LinuxAdapter):
    def get_system_info(self):
        info = super().get_system_info()
        info["os"] = "Android (Termux)"
        return info

    def get_context_metrics(self):
        metrics = super().get_context_metrics()
        # Android specific triggers (example: foreground app via termux-api if available)
        return metrics

def get_adapter():
    system = platform.system().lower()
    if system == "linux":
        # Check for Android/Termux environment
        if "ANDROID_ROOT" in os.environ:
            return AndroidAdapter()
        return LinuxAdapter()
    # Fallback or other platform adapters...
    return LinuxAdapter()
