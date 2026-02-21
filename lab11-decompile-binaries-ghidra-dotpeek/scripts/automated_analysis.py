#!/usr/bin/env python3
"""
Automated binary analysis using Ghidra headless mode

This script:
- Creates/uses a Ghidra headless project
- Imports binaries for analysis
- Runs a post-analysis Ghidra script (FindVulnerabilities.java) if present
- Collects results and generates a JSON report
"""

import subprocess
import os
import json
from pathlib import Path
from datetime import datetime


class GhidraAnalyzer:
    def __init__(self, ghidra_path, project_path):
        """
        Initialize Ghidra analyzer

        Args:
        ghidra_path: Path to Ghidra installation
        project_path: Path for analysis projects
        """
        self.ghidra_path = Path(ghidra_path).expanduser().resolve()
        self.project_path = Path(project_path).expanduser().resolve()
        self.project_path.mkdir(parents=True, exist_ok=True)

        self.headless_script = self.ghidra_path / "support" / "analyzeHeadless"
        if not self.headless_script.exists():
            raise FileNotFoundError(f"analyzeHeadless not found at: {self.headless_script}")

        # Optional post-analysis script name
        self.post_script_name = "FindVulnerabilities.java"

    def analyze_binary(self, binary_path, project_name="AutoAnalysis"):
        """
        Analyze binary using Ghidra headless mode
        """
        binary_path = Path(binary_path).expanduser().resolve()
        if not binary_path.exists():
            return {
                "binary": str(binary_path),
                "status": "failed",
                "error": "Binary does not exist"
            }

        cmd = [
            str(self.headless_script),
            str(self.project_path),
            project_name,
            "-import", str(binary_path),
            "-analysisTimeoutPerFile", "300",
            "-overwrite"
        ]

        local_script_path = (Path.cwd() / "scripts").resolve()
        post_script_file = local_script_path / self.post_script_name

        if post_script_file.exists():
            cmd.extend(["-scriptPath", str(local_script_path), "-postScript", self.post_script_name])

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )

            result = {
                "binary": str(binary_path),
                "project_name": project_name,
                "command": cmd,
                "return_code": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "status": "success" if completed.returncode == 0 else "failed",
                "analyzed_at": datetime.now().isoformat()
            }

            findings = []
            out_text = (completed.stdout or "") + "\n" + (completed.stderr or "")
            for keyword in ["strcpy", "strcat", "sprintf", "gets", "system", "printf"]:
                if keyword in out_text:
                    findings.append(f"Possible reference to {keyword} found in headless output/logs")

            result["quick_findings"] = findings
            return result

        except subprocess.TimeoutExpired:
            return {
                "binary": str(binary_path),
                "project_name": project_name,
                "status": "failed",
                "error": "Headless analysis timed out",
                "analyzed_at": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "binary": str(binary_path),
                "project_name": project_name,
                "status": "failed",
                "error": str(e),
                "analyzed_at": datetime.now().isoformat()
            }

    def batch_analyze(self, binary_directory):
        """
        Analyze multiple binaries in directory
        """
        binary_directory = Path(binary_directory).expanduser().resolve()
        results = []

        if not binary_directory.exists():
            return [{
                "status": "failed",
                "error": f"Binary directory does not exist: {binary_directory}"
            }]

        candidates = []
        for p in binary_directory.iterdir():
            if p.is_file():
                if p.suffix.lower() in [".c", ".cs", ".md", ".txt", ".json", ".zip"]:
                    continue
                if p.suffix.lower() == ".exe":
                    candidates.append(p)
                    continue
                if os.access(str(p), os.X_OK):
                    candidates.append(p)

        known = binary_directory / "vulnerable_app"
        if known.exists() and known not in candidates:
            candidates.append(known)

        for bin_file in sorted(candidates):
            project_name = f"AutoAnalysis_{bin_file.name}"
            res = self.analyze_binary(bin_file, project_name=project_name)
            results.append(res)

        return results


def generate_report(results, output_file):
    output_file = Path(output_file).expanduser().resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)

    total = len(results)
    success = sum(1 for r in results if r.get("status") == "success")
    failed = total - success

    report = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_targets": total,
            "successful": success,
            "failed": failed
        },
        "results": results
    }

    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Saved analysis report to {output_file}")
    print("Summary:", report["summary"])


def main():
    config = {
        "ghidra_path": "~/lab11-binary-analysis/ghidra",
        "project_path": "~/lab11-binary-analysis/automated_analysis/ghidra_projects",
        "binary_directory": "~/lab11-binary-analysis",
        "report_path": "~/lab11-binary-analysis/automated_analysis/analysis_report.json"
    }

    ghidra_path = Path(config["ghidra_path"]).expanduser().resolve()
    project_path = Path(config["project_path"]).expanduser().resolve()
    binary_directory = Path(config["binary_directory"]).expanduser().resolve()
    report_path = Path(config["report_path"]).expanduser().resolve()

    analyzer = GhidraAnalyzer(str(ghidra_path), str(project_path))
    results = analyzer.batch_analyze(str(binary_directory))
    generate_report(results, str(report_path))


if __name__ == "__main__":
    main()
