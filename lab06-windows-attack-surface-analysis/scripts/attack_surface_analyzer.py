#!/usr/bin/env python3
import psutil
import socket
import json
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

class AttackSurfaceAnalyzer:
    def __init__(self):
        self.analysis_results = {
            "timestamp": datetime.now().isoformat(),
            "network_exposure": {},
            "process_analysis": {},
            "vulnerabilities": []
        }

    def analyze_network_exposure(self):
        """
        Analyze network attack surface.

        - Use psutil.net_connections() to get listening ports
        - Identify processes bound to each port
        - Flag high-risk ports (21, 23, 3389, etc.)
        - Store results in self.analysis_results
        """
        high_risk_ports = {
            21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP",
            139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
            3389: "RDP", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch"
        }

        listeners = []
        vulns = []

        try:
            conns = psutil.net_connections(kind="inet")
        except Exception as e:
            self.analysis_results["network_exposure"] = {"error": str(e)}
            return

        for c in conns:
            if c.status != psutil.CONN_LISTEN:
                continue

            laddr = c.laddr
            if not laddr:
                continue

            ip = laddr.ip if hasattr(laddr, "ip") else laddr[0]
            port = laddr.port if hasattr(laddr, "port") else laddr[1]
            pid = c.pid

            proc_name = ""
            user = ""
            try:
                if pid:
                    p = psutil.Process(pid)
                    proc_name = p.name()
                    user = p.username()
            except Exception:
                proc_name = ""
                user = ""

            service_guess = high_risk_ports.get(port, "")

            if port in high_risk_ports:
                vulns.append({
                    "type": "High-Risk Open Port",
                    "severity": "HIGH",
                    "detail": f"Port {port} ({high_risk_ports[port]}) is listening on {ip}",
                    "pid": pid,
                    "process": proc_name
                })

            listeners.append({
                "ip": ip,
                "port": port,
                "pid": pid,
                "process": proc_name,
                "user": user,
                "service_hint": service_guess
            })

        self.analysis_results["network_exposure"] = {
            "listening_ports": listeners,
            "total_listeners": len(listeners)
        }
        self.analysis_results["vulnerabilities"].extend(vulns)

    def analyze_process_security(self):
        """
        Analyze process security posture.

        - Enumerate processes with user context
        - Identify root/privileged processes
        - Check for processes with network connections
        - Flag suspicious combinations (root + network)
        """
        privileged = []
        suspicious = []

        pids_with_net = set()
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.pid:
                    pids_with_net.add(c.pid)
        except Exception:
            pass

        for proc in psutil.process_iter(attrs=["pid", "name", "username", "cmdline"]):
            try:
                info = proc.info
                pid = info.get("pid")
                name = info.get("name") or ""
                user = info.get("username") or ""
                cmd = " ".join(info.get("cmdline") or [])[:200]

                is_priv = (user == "root")
                has_net = pid in pids_with_net

                if is_priv:
                    privileged.append({
                        "pid": pid,
                        "name": name,
                        "user": user,
                        "cmd": cmd,
                        "network": has_net
                    })

                if is_priv and has_net:
                    suspicious.append({
                        "pid": pid,
                        "name": name,
                        "user": user,
                        "cmd": cmd,
                        "reason": "root + network"
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

        self.analysis_results["process_analysis"] = {
            "privileged_processes": privileged,
            "suspicious_processes": suspicious,
            "privileged_count": len(privileged),
            "suspicious_count": len(suspicious)
        }

        for s in suspicious:
            self.analysis_results["vulnerabilities"].append({
                "type": "Privileged Process with Network",
                "severity": "MEDIUM",
                "detail": f"Process {s['name']} (PID {s['pid']}) running as root has network activity",
                "pid": s["pid"],
                "process": s["name"]
            })

    def calculate_risk_score(self):
        """
        Calculate overall risk score (0-100).
        """
        listeners = self.analysis_results.get("network_exposure", {}).get("listening_ports", [])
        open_ports_score = min(30, len(listeners) * 3)

        priv_count = self.analysis_results.get("process_analysis", {}).get("privileged_count", 0)
        priv_score = min(25, priv_count * 2)

        vulns = self.analysis_results.get("vulnerabilities", [])
        high = len([v for v in vulns if v.get("severity") == "HIGH"])
        med = len([v for v in vulns if v.get("severity") == "MEDIUM"])
        low = len([v for v in vulns if v.get("severity") == "LOW"])

        vuln_score = min(45, high * 15 + med * 8 + low * 3)

        total = open_ports_score + priv_score + vuln_score
        if total > 100:
            total = 100

        self.analysis_results["risk_score"] = {
            "open_ports_score": open_ports_score,
            "privileged_process_score": priv_score,
            "vulnerability_score": vuln_score,
            "total": total
        }
        return total

    def generate_report(self):
        """
        Print a human-readable report to terminal.
        """
        print(f"{Fore.CYAN}{'='*70}")
        print(" ATTACK SURFACE ANALYZER REPORT")
        print(f"{'='*70}{Style.RESET_ALL}")

        net = self.analysis_results.get("network_exposure", {})
        proc = self.analysis_results.get("process_analysis", {})
        vulns = self.analysis_results.get("vulnerabilities", [])
        score = self.analysis_results.get("risk_score", {}).get("total", 0)

        print(f"{Fore.GREEN}[+] Timestamp:{Style.RESET_ALL} {self.analysis_results.get('timestamp')}")
        print("")

        print(f"{Fore.YELLOW}Network Exposure{Style.RESET_ALL}")
        listeners = net.get("listening_ports", [])
        print(f"- Total listening ports: {net.get('total_listeners', 0)}")
        for l in listeners[:20]:
            print(f"  - {l['ip']}:{l['port']} pid={l['pid']} proc={l['process']} user={l['user']}")

        print("")
        print(f"{Fore.YELLOW}Process Security Summary{Style.RESET_ALL}")
        print(f"- Privileged processes (root): {proc.get('privileged_count', 0)}")
        print(f"- Suspicious privileged+network: {proc.get('suspicious_count', 0)}")

        print("")
        print(f"{Fore.YELLOW}Identified Vulnerabilities{Style.RESET_ALL}")
        if not vulns:
            print(f"{Fore.GREEN}- None identified by heuristic checks.{Style.RESET_ALL}")
        else:
            for v in vulns[:50]:
                sev = v.get("severity", "LOW")
                color = Fore.RED if sev == "HIGH" else (Fore.YELLOW if sev == "MEDIUM" else Fore.WHITE)
                print(f"{color}- [{sev}] {v.get('type')}: {v.get('detail')}{Style.RESET_ALL}")

        print("")
        print(f"{Fore.CYAN}Overall Risk Score: {score}/100{Style.RESET_ALL}")

    def save_report(self, filename="attack_surface_report.json"):
        """
        Save analysis results to JSON file.
        """
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.analysis_results, f, indent=2)
        print(f"{Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")

def main():
    analyzer = AttackSurfaceAnalyzer()
    analyzer.analyze_network_exposure()
    analyzer.analyze_process_security()
    analyzer.calculate_risk_score()
    analyzer.generate_report()
    analyzer.save_report("attack_surface_report.json")

if __name__ == "__main__":
    main()
