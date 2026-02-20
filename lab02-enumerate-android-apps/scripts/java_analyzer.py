#!/usr/bin/env python3
import os
import re
import json
from pathlib import Path

class JavaCodeAnalyzer:
    def __init__(self, source_dir):
        self.source_dir = source_dir
        self.vulnerabilities = []

    def find_java_files(self):
        """
        Find all Java files in the source directory
        """
        java_files = []
        for root, dirs, files in os.walk(self.source_dir):
            for fn in files:
                if fn.endswith(".java"):
                    java_files.append(os.path.join(root, fn))
        return java_files

    def _add_finding(self, severity, category, file_path, detail, evidence=None):
        item = {
            "severity": severity,
            "category": category,
            "file": file_path,
            "detail": detail
        }
        if evidence is not None:
            item["evidence"] = evidence
        self.vulnerabilities.append(item)

    def analyze_hardcoded_secrets(self, file_path):
        """
        Analyze file for hardcoded secrets
        """
        patterns = [
            ("HIGH", "Hardcoded Password", re.compile(r'(password|pwd)\s*[=:]\s*["\']([^"\']+)["\']', re.IGNORECASE)),
            ("HIGH", "Hardcoded API Key", re.compile(r'(api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']+)["\']', re.IGNORECASE)),
            ("HIGH", "Hardcoded Token/Secret", re.compile(r'(secret|token)\s*[=:]\s*["\']([^"\']+)["\']', re.IGNORECASE)),
        ]

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return

        for severity, category, rx in patterns:
            for m in rx.finditer(content):
                evidence = m.group(0)[:200]
                self._add_finding(
                    severity=severity,
                    category=category,
                    file_path=file_path,
                    detail="Potential hardcoded secret found",
                    evidence=evidence
                )

    def analyze_sql_injection(self, file_path):
        """
        Check for SQL injection vulnerabilities
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return

        rawquery_concat = re.compile(r'rawQuery\s*\(\s*".*"\s*\+\s*.*\)', re.IGNORECASE)
        execsql_concat = re.compile(r'execSQL\s*\(\s*".*"\s*\+\s*.*\)', re.IGNORECASE)

        for idx, line in enumerate(lines, start=1):
            if rawquery_concat.search(line):
                self._add_finding(
                    severity="MEDIUM",
                    category="Potential SQL Injection (rawQuery)",
                    file_path=file_path,
                    detail=f"rawQuery appears to use string concatenation at line {idx}",
                    evidence=line.strip()[:200]
                )
            if execsql_concat.search(line):
                self._add_finding(
                    severity="MEDIUM",
                    category="Potential SQL Injection (execSQL)",
                    file_path=file_path,
                    detail=f"execSQL appears to use string concatenation at line {idx}",
                    evidence=line.strip()[:200]
                )

    def analyze_insecure_connections(self, file_path):
        """
        Check for insecure HTTP connections
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return

        for m in re.finditer(r'http://[^\s"\'<>]+', content, flags=re.IGNORECASE):
            url = m.group(0)
            self._add_finding(
                severity="MEDIUM",
                category="Insecure HTTP Connection",
                file_path=file_path,
                detail="Found hardcoded http:// URL (use https://)",
                evidence=url[:200]
            )

    def analyze_webview_security(self, file_path):
        """
        Check for WebView security issues
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return

        js_enabled = re.compile(r'setJavaScriptEnabled\s*\(\s*true\s*\)', re.IGNORECASE)
        add_js_iface = re.compile(r'addJavascriptInterface\s*\(', re.IGNORECASE)

        for idx, line in enumerate(lines, start=1):
            if js_enabled.search(line):
                self._add_finding(
                    severity="MEDIUM",
                    category="WebView JavaScript Enabled",
                    file_path=file_path,
                    detail=f"WebView JavaScript enabled at line {idx} (review XSS risk)",
                    evidence=line.strip()[:200]
                )
            if add_js_iface.search(line):
                self._add_finding(
                    severity="HIGH",
                    category="addJavascriptInterface Used",
                    file_path=file_path,
                    detail=f"addJavascriptInterface at line {idx} (high risk on old Android versions)",
                    evidence=line.strip()[:200]
                )

    def run_analysis(self):
        """
        Run comprehensive analysis on all Java files
        """
        java_files = self.find_java_files()
        for fp in java_files:
            self.analyze_hardcoded_secrets(fp)
            self.analyze_sql_injection(fp)
            self.analyze_insecure_connections(fp)
            self.analyze_webview_security(fp)
        return self.vulnerabilities

    def generate_report(self, output_file):
        """
        Generate JSON analysis report
        """
        vulns = self.run_analysis()

        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in vulns:
            sev = v.get("severity", "LOW").upper()
            if sev not in severity_counts:
                severity_counts[sev] = 0
            severity_counts[sev] += 1

        report = {
            "source_dir": self.source_dir,
            "total_findings": len(vulns),
            "severity_counts": severity_counts,
            "findings": vulns
        }

        Path(os.path.dirname(output_file) or ".").mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        print("[+] Java analysis complete")
        print(f"[+] Report saved to: {output_file}")
        print(f"[+] Total findings: {report['total_findings']}")
        print(f"[+] Severity counts: {report['severity_counts']}")

        return report


def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 java_analyzer.py <source_directory>")
        sys.exit(1)

    source_dir = sys.argv[1]

    if not os.path.isdir(source_dir):
        print(f"[-] Directory not found: {source_dir}")
        sys.exit(1)

    analyzer = JavaCodeAnalyzer(source_dir)

    output_file = os.path.join(os.getcwd(), "java_analysis_report.json")
    analyzer.generate_report(output_file)


if __name__ == "__main__":
    main()
