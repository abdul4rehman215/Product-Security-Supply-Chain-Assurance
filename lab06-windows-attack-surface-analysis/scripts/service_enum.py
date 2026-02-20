#!/usr/bin/env python3
import subprocess
from tabulate import tabulate
from colorama import init, Fore, Style

init(autoreset=True)

class ServiceEnumerator:
    def __init__(self):
        self.services = []
        self.net_listeners = []

    def enumerate_systemd_services(self):
        """
        Enumerate systemd services using systemctl.
        """
        cmd = ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"]
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = p.stdout.splitlines()
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to run systemctl: {e}{Style.RESET_ALL}")
            return

        self.services = []
        for line in output:
            line = line.rstrip()
            if not line:
                continue

            parts = line.split(None, 4)
            if len(parts) < 5:
                continue

            unit, load, active, sub, desc = parts
            self.services.append({
                "unit": unit,
                "load": load,
                "active": active,
                "sub": sub,
                "description": desc
            })

    def display_services(self):
        """
        Display active services.
        """
        if not self.services:
            print(f"{Fore.YELLOW}[!] No service data collected. Run enumerate_systemd_services() first.{Style.RESET_ALL}")
            return

        active_svcs = [s for s in self.services if s["active"].lower() == "active"]

        table = []
        for s in active_svcs[:30]:
            table.append([s["unit"], s["load"], s["active"], s["sub"], s["description"]])

        print(f"{Fore.GREEN}[+] Active systemd services (showing up to 30){Style.RESET_ALL}")
        print(tabulate(table, headers=["Service", "Load", "Active", "Sub", "Description"], tablefmt="github"))
        print(f"{Fore.CYAN}[i] Total active services: {len(active_svcs)}{Style.RESET_ALL}")

    def analyze_network_services(self):
        """
        Analyze network-listening services.
        """
        cmd = ["ss", "-tlnp"]
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out = p.stdout.splitlines()
            if p.returncode != 0 or len(out) == 0:
                raise RuntimeError("ss failed or returned empty output")
            raw = out
            parser = "ss"
        except Exception:
            cmd = ["netstat", "-tlnp"]
            try:
                p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                raw = p.stdout.splitlines()
                parser = "netstat"
            except Exception as e:
                print(f"{Fore.RED}[-] Failed to run ss or netstat: {e}{Style.RESET_ALL}")
                return

        listeners = []

        if parser == "ss":
            for line in raw:
                if line.startswith("State") or line.startswith("Netid"):
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue

                local = parts[3]
                proto = parts[0]
                proc_info = ""
                if "users:(" in line:
                    proc_info = line.split("users:(", 1)[1].rstrip(")")

                listeners.append({
                    "proto": proto,
                    "local": local,
                    "process": proc_info
                })
        else:
            for line in raw:
                if line.startswith("Proto") or line.startswith("Active"):
                    continue
                parts = line.split()
                if len(parts) < 7:
                    continue

                proto = parts[0]
                local = parts[3]
                state = parts[5] if proto.startswith("tcp") else ""
                pidprog = parts[6] if len(parts) >= 7 else ""

                if proto.startswith("tcp") and state != "LISTEN":
                    continue

                listeners.append({
                    "proto": proto,
                    "local": local,
                    "process": pidprog
                })

        self.net_listeners = listeners

        print("")
        print(f"{Fore.CYAN}[+] Network Listening Services Summary{Style.RESET_ALL}")

        if not listeners:
            print(f"{Fore.YELLOW}[!] No listening services found or insufficient permissions.{Style.RESET_ALL}")
            return

        table = []
        for l in listeners[:40]:
            table.append([l["proto"], l["local"], l["process"]])

        print(tabulate(table, headers=["Proto", "Local Address", "Process"], tablefmt="github"))
        print(f"{Fore.CYAN}[i] Total listeners: {len(listeners)}{Style.RESET_ALL}")

def main():
    print(f"{Fore.CYAN}{'='*60}")
    print(f" SERVICE ENUMERATION TOOL")
    print(f"{'='*60}{Style.RESET_ALL}")

    se = ServiceEnumerator()
    se.enumerate_systemd_services()
    se.display_services()
    se.analyze_network_services()

if __name__ == "__main__":
    main()
