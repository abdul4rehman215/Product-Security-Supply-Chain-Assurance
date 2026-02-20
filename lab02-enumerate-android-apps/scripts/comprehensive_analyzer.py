#!/usr/bin/env python3
import os
import json
import subprocess
import argparse
import datetime
from pathlib import Path

class ComprehensiveAPKAnalyzer:
    def __init__(self, apk_path, output_dir):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.results = {
            "apk_info": {},
            "apktool_analysis": {},
            "jadx_analysis": {},
            "apkleaks_analysis": {},
            "summary": {}
        }
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

        # Internal paths
        self.apktool_dir = os.path.join(self.output_dir, "apktool_decompiled")
        self.jadx_dir = os.path.join(self.output_dir, "jadx_decompiled")
        self.apkleaks_json = os.path.join(self.output_dir, "apkleaks_report.json")

    def _run(self, cmd, cwd=None, timeout=600):
        try:
            p = subprocess.run(
                cmd,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
            return p.returncode, p.stdout, p.stderr
        except FileNotFoundError:
            return 127, "", f"Command not found: {cmd[0]}"
        except subprocess.TimeoutExpired:
            return 124, "", "Command timed out"
        except Exception as e:
            return 1, "", str(e)

    def get_apk_info(self):
        """
        Extract basic APK information using aapt

        - Run 'aapt dump badging' command
        - Parse output for package name, version code, version name
        - Store in self.results['apk_info']
        """
        cmd = ["aapt", "dump", "badging", self.apk_path]
        rc, out, err = self._run(cmd)

        if rc != 0:
            self.results["apk_info"] = {
                "error": "aapt dump badging failed",
                "stderr": (err or "").strip(),
                "note": "If aapt is not available, install android-sdk-build-tools or ensure aapt exists."
            }
            return False

        package_name = None
        version_code = None
        version_name = None

        for line in out.splitlines():
            if line.startswith("package:"):
                def extract(field):
                    if f"{field}='" in line:
                        start = line.find(f"{field}='") + len(f"{field}='")
                        end = line.find("'", start)
                        return line[start:end]
                    return None

                package_name = extract("name")
                version_code = extract("versionCode")
                version_name = extract("versionName")
                break

        self.results["apk_info"] = {
            "package_name": package_name,
            "version_code": version_code,
            "version_name": version_name,
            "tool": "aapt",
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
        }
        return True

    def run_apktool_analysis(self):
        """
        Run apktool decompilation and analyze manifest
        """
        analysis = {
            "decompiled_dir": self.apktool_dir,
            "decompile_status": "NOT_RUN",
            "issues": [],
            "manifest_path": None
        }

        cmd = ["apktool", "d", "-f", self.apk_path, "-o", self.apktool_dir]
        rc, out, err = self._run(cmd, timeout=900)

        if rc != 0:
            analysis["decompile_status"] = "FAILED"
            analysis["stderr"] = (err or "").strip()
            self.results["apktool_analysis"] = analysis
            return False

        analysis["decompile_status"] = "SUCCESS"

        manifest_path = os.path.join(self.apktool_dir, "AndroidManifest.xml")
        analysis["manifest_path"] = manifest_path

        if not os.path.exists(manifest_path):
            analysis["issues"].append("AndroidManifest.xml not found after apktool decompilation")
            self.results["apktool_analysis"] = analysis
            return False

        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            manifest = f.read()

        if "android:debuggable=\"true\"" in manifest or "debuggable=\"true\"" in manifest:
            analysis["issues"].append("Debug mode enabled: android:debuggable=\"true\"")

        if "android:allowBackup=\"true\"" in manifest:
            analysis["issues"].append("Backup enabled: android:allowBackup=\"true\"")

        if "android:exported=\"true\"" in manifest:
            analysis["issues"].append("Exported components found: android:exported=\"true\" (review access control)")

        if "android:usesCleartextTraffic=\"true\"" in manifest:
            analysis["issues"].append("Cleartext traffic allowed: android:usesCleartextTraffic=\"true\"")

        self.results["apktool_analysis"] = analysis
        return True

    def run_jadx_analysis(self):
        """
        Run JADX decompilation
        """
        analysis = {
            "output_dir": self.jadx_dir,
            "decompile_status": "NOT_RUN",
            "java_file_count": 0,
            "issues": []
        }

        cmd = ["jadx", "-d", self.jadx_dir, self.apk_path]
        rc, out, err = self._run(cmd, timeout=1200)

        if rc != 0:
            analysis["decompile_status"] = "FAILED"
            analysis["stderr"] = (err or "").strip()
            self.results["jadx_analysis"] = analysis
            return False

        analysis["decompile_status"] = "SUCCESS"

        java_files = []
        for root, dirs, files in os.walk(self.jadx_dir):
            for fn in files:
                if fn.endswith(".java"):
                    java_files.append(os.path.join(root, fn))
        analysis["java_file_count"] = len(java_files)

        self.results["jadx_analysis"] = analysis
        return True

    def run_apkleaks_analysis(self):
        """
        Run apkleaks secret extraction
        """
        analysis = {
            "json_report": self.apkleaks_json,
            "run_status": "NOT_RUN",
            "secrets_count": 0,
            "secrets": [],
            "issues": []
        }

        cmd = ["apkleaks", "-f", self.apk_path, "-o", self.apkleaks_json, "--json"]
        rc, out, err = self._run(cmd, timeout=1200)

        if rc != 0:
            analysis["run_status"] = "FAILED"
            analysis["stderr"] = (err or "").strip()
            self.results["apkleaks_analysis"] = analysis
            return False

        analysis["run_status"] = "SUCCESS"

        if not os.path.exists(self.apkleaks_json):
            analysis["issues"].append("apkleaks JSON output file not created")
            self.results["apkleaks_analysis"] = analysis
            return False

        try:
            with open(self.apkleaks_json, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        except Exception as e:
            analysis["issues"].append(f"Failed to parse apkleaks JSON: {e}")
            self.results["apkleaks_analysis"] = analysis
            return False

        secrets_found = []
        if isinstance(data, dict):
            for k in ["results", "findings", "matches", "secrets"]:
                if k in data and isinstance(data[k], list):
                    secrets_found = data[k]
                    break
            if not secrets_found and "data" in data and isinstance(data["data"], list):
                secrets_found = data["data"]
        elif isinstance(data, list):
            secrets_found = data

        analysis["secrets"] = secrets_found
        analysis["secrets_count"] = len(secrets_found)

        self.results["apkleaks_analysis"] = analysis
        return True

    def generate_summary(self):
        """
        Generate analysis summary
        """
        total_issues = 0
        critical_findings = []
        recommendations = []

        apktool_issues = self.results.get("apktool_analysis", {}).get("issues", [])
        total_issues += len(apktool_issues)

        secrets_count = self.results.get("apkleaks_analysis", {}).get("secrets_count", 0)
        if secrets_count:
            total_issues += secrets_count

        for issue in apktool_issues:
            if "Debug mode enabled" in issue or "Cleartext traffic allowed" in issue:
                critical_findings.append(issue)

        if secrets_count > 0:
            critical_findings.append(f"Potential secrets detected by apkleaks: {secrets_count}")

        if any("Debug mode enabled" in i for i in apktool_issues):
            recommendations.append("Disable debug mode before production release (android:debuggable should be false).")
        if any("Backup enabled" in i for i in apktool_issues):
            recommendations.append("Disable android:allowBackup for sensitive apps or implement secure backup policies.")
        if any("Exported components" in i for i in apktool_issues):
            recommendations.append("Review exported components and enforce permissions/authentication where needed.")
        if any("Cleartext traffic allowed" in i for i in apktool_issues):
            recommendations.append("Disallow cleartext traffic; enforce HTTPS and network security config.")
        if secrets_count > 0:
            recommendations.append("Remove hardcoded secrets; rotate any exposed keys/tokens and use secure storage.")

        self.results["summary"] = {
            "total_issues": total_issues,
            "critical_findings": critical_findings,
            "recommendations": recommendations,
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z"
        }
        return self.results["summary"]

    def save_results(self):
        """
        Save analysis results to JSON file
        """
        out_file = os.path.join(self.output_dir, "comprehensive_analysis.json")
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2)

        print(f"[+] Comprehensive analysis saved to: {out_file}")

        summary = self.results.get("summary", {})
        print("[+] Summary:")
        print(json.dumps(summary, indent=2))

        return out_file

    def run_full_analysis(self):
        """
        Run complete APK analysis pipeline
        """
        print(f"[+] Starting comprehensive analysis for: {self.apk_path}")
        self.get_apk_info()
        self.run_apktool_analysis()
        self.run_jadx_analysis()
        self.run_apkleaks_analysis()
        self.generate_summary()
        return self.save_results()

def main():
    parser = argparse.ArgumentParser(description='Comprehensive APK Security Analyzer')
    parser.add_argument('apk_path', help='Path to APK file')
    parser.add_argument('-o', '--output', default='analysis_output', help='Output directory')

    args = parser.parse_args()

    if not os.path.isfile(args.apk_path):
        print(f"[-] APK file not found: {args.apk_path}")
        raise SystemExit(1)

    analyzer = ComprehensiveAPKAnalyzer(args.apk_path, args.output)
    analyzer.run_full_analysis()

if __name__ == "__main__":
    main()
