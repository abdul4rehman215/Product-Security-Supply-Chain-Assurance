#!/usr/bin/env python3

import subprocess
import sys
import os

class ReconNGScanner:
    def __init__(self, workspace="product_recon"):
        self.workspace = workspace
        self.recon_path = os.path.expanduser("~/osint-lab/recon-ng")

    def run_command(self, commands):
        process = subprocess.Popen(
            ["python3", "recon-ng", "-r", "-"],
            cwd=self.recon_path,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(commands)
        return stdout

    def execute_workflow(self, domain):
        commands = f"""
workspaces create {self.workspace}
workspaces select {self.workspace}
marketplace install recon/domains-hosts/hackertarget
marketplace install recon/domains-hosts/threatcrowd
marketplace install recon/domains-hosts/resolve
db insert domains {domain}
modules load recon/domains-hosts/hackertarget
run
modules load recon/domains-hosts/threatcrowd
run
modules load recon/domains-hosts/resolve
run
show hosts
exit
"""
        return self.run_command(commands)


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 reconng_scanner.py <target_domain>")
        sys.exit(1)

    target = sys.argv[1]
    scanner = ReconNGScanner()
    print(f"Starting recon-ng scan for: {target}")
    results = scanner.execute_workflow(target)
    print(results)


if __name__ == "__main__":
    main()
