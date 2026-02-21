#!/usr/bin/env python3

import json
import glob


class FuzzingResultsAnalyzer:
    """Analyze and report on fuzzing results"""

    def __init__(self):
        self.results_data = []

    def load_results(self, pattern="vulnerability_report_*.json"):
        files = sorted(glob.glob(pattern))
        self.results_data = []

        for fpath in files:
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    data["_file"] = fpath
                    self.results_data.append(data)
            except Exception as e:
                print(f"Failed to load {fpath}: {e}")

    def analyze_crash_patterns(self):
        crash_data = {}

        for report in self.results_data:
            protocols = report.get("protocols", {})
            for proto_name, pdata in protocols.items():
                crash_count = pdata.get("crashes_detected", 0)
                crash_data[proto_name] = crash_data.get(proto_name, 0) + int(crash_count)

        return crash_data

    def print_summary_report(self):
        self.load_results()
        crash_patterns = self.analyze_crash_patterns()

        print("=== Fuzzing Results Summary ===")
        print(f"Reports loaded: {len(self.results_data)}")

        print("\n=== Crash Patterns by Protocol ===")
        for proto, count in crash_patterns.items():
            print(f"{proto}: {count}")


if __name__ == "__main__":
    analyzer = FuzzingResultsAnalyzer()
    analyzer.print_summary_report()
