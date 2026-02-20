#!/usr/bin/env python3
import psutil
from tabulate import tabulate
from colorama import init, Fore, Style

init(autoreset=True)

class ProcessEnumerator:
    def __init__(self):
        self.processes = []

    def enumerate_processes(self):
        """
        Enumerate all running processes with detailed information.

        - Iterate through psutil.process_iter()
        - Collect pid, name, username, cpu_percent, memory_info, cmdline
        - Handle exceptions for inaccessible processes
        - Store results in self.processes list
        """
        self.processes = []

        # Prime CPU percent calculation
        for p in psutil.process_iter(attrs=["pid"]):
            try:
                p.cpu_percent(interval=None)
            except Exception:
                continue

        for proc in psutil.process_iter(attrs=["pid", "name", "username", "cpu_percent", "memory_info", "cmdline"]):
            try:
                info = proc.info
                pid = info.get("pid")
                name = info.get("name") or ""
                username = info.get("username") or ""
                cpu = proc.cpu_percent(interval=0.05)
                meminfo = info.get("memory_info")
                rss = meminfo.rss if meminfo else 0
                cmdline = info.get("cmdline") or []
                cmd_str = " ".join(cmdline)[:200] if cmdline else ""

                self.processes.append({
                    "pid": pid,
                    "name": name,
                    "username": username,
                    "cpu_percent": float(cpu),
                    "memory_rss": int(rss),
                    "cmdline": cmd_str
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

    def display_processes(self):
        """
        Display processes in formatted table sorted by CPU usage.
        """
        if not self.processes:
            print(f"{Fore.YELLOW}[!] No process data collected. Run enumerate_processes() first.{Style.RESET_ALL}")
            return

        procs_sorted = sorted(self.processes, key=lambda x: x["cpu_percent"], reverse=True)

        table = []
        for p in procs_sorted[:20]:
            table.append([
                p["pid"],
                p["name"],
                p["username"],
                f"{p['cpu_percent']:.1f}",
                f"{p['memory_rss'] / (1024*1024):.1f} MB",
                p["cmdline"]
            ])

        print(f"{Fore.GREEN}[+] Top 20 Processes by CPU Usage{Style.RESET_ALL}")
        print(tabulate(table, headers=["PID", "Name", "User", "CPU%", "Memory", "Command"], tablefmt="github"))

    def find_suspicious_processes(self):
        """
        Identify potentially suspicious processes.
        """
        if not self.processes:
            print(f"{Fore.YELLOW}[!] No process data collected. Run enumerate_processes() first.{Style.RESET_ALL}")
            return

        suspicious_indicators = [
            "nc", "netcat", "ncat", "socat",
            "bash -i", "python -c", "perl -e",
            "powershell", "cmd.exe", "mshta",
            "reverse", "meterpreter"
        ]

        # Build set of PIDs with network connections
        pids_with_net = set()
        try:
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                if c.pid:
                    pids_with_net.add(c.pid)
        except Exception:
            pass

        findings = []
        for p in self.processes:
            name_l = (p["name"] or "").lower()
            cmd_l = (p["cmdline"] or "").lower()

            indicator_hit = None
            for ind in suspicious_indicators:
                if ind in name_l or ind in cmd_l:
                    indicator_hit = ind
                    break

            net_flag = p["pid"] in pids_with_net

            if indicator_hit or net_flag:
                findings.append({
                    "pid": p["pid"],
                    "name": p["name"],
                    "user": p["username"],
                    "indicator": indicator_hit if indicator_hit else "",
                    "net": "YES" if net_flag else "NO",
                    "cmd": p["cmdline"]
                })

        print("")
        print(f"{Fore.CYAN}[+] Suspicious Process Check{Style.RESET_ALL}")

        if not findings:
            print(f"{Fore.GREEN}[+] No obvious suspicious processes found based on simple indicators.{Style.RESET_ALL}")
            return

        table = []
        for f in findings:
            color = Fore.RED if f["indicator"] else (Fore.YELLOW if f["net"] == "YES" else Fore.WHITE)
            table.append([
                f"{color}{f['pid']}{Style.RESET_ALL}",
                f"{color}{f['name']}{Style.RESET_ALL}",
                f"{color}{f['user']}{Style.RESET_ALL}",
                f"{color}{f['indicator']}{Style.RESET_ALL}",
                f"{color}{f['net']}{Style.RESET_ALL}",
                f"{color}{f['cmd']}{Style.RESET_ALL}"
            ])

        print(tabulate(table, headers=["PID", "Name", "User", "Indicator", "NetConn", "Command"], tablefmt="github"))

def main():
    print(f"{Fore.CYAN}{'='*60}")
    print(f" PROCESS ENUMERATION TOOL")
    print(f"{'='*60}{Style.RESET_ALL}")

    pe = ProcessEnumerator()
    pe.enumerate_processes()
    pe.display_processes()
    pe.find_suspicious_processes()

if __name__ == "__main__":
    main()
