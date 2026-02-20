#!/usr/bin/env python3
# File: automated_analysis.py

import subprocess
import time
import os
from datetime import datetime

class NetworkAnalysisPipeline:

    def __init__(self, duration=60):
        self.duration = duration
        self.capture_process = None
        self.traffic_process = None

    def start_capture(self, interface='any'):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pcap_file = f'analysis_output/capture_{timestamp}.pcap'

        self.capture_process = subprocess.Popen(
            ['tshark', '-i', interface, '-w', pcap_file, '-f', 'not port 22'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return pcap_file

    def start_traffic_generation(self):
        self.traffic_process = subprocess.Popen(
            ['python3', 'traffic_generator.py']
        )

    def wait_for_completion(self):
        time.sleep(self.duration)

    def process_data(self, pcap_file):
        csv_file = pcap_file.replace('.pcap', '.csv')

        subprocess.run(['python3', 'pcap_converter.py', pcap_file, csv_file])
        subprocess.run(['python3', 'create_procmon_log.py'])
        subprocess.run(['python3', 'network_visualizer.py'])

        return csv_file

    def generate_report(self, pcap_file, csv_file):
        report_file = f"analysis_output/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        with open(report_file, 'w') as f:
            f.write("=== Network Analysis Report ===\n\n")
            f.write(f"PCAP File: {pcap_file}\n")
            f.write(f"CSV File: {csv_file}\n\n")

            stats = subprocess.run(
                ['tshark', '-r', pcap_file, '-q', '-z', 'io,phs'],
                capture_output=True,
                text=True
            )

            f.write(stats.stdout)

        print(f"[+] Report generated: {report_file}")
        return report_file

    def cleanup(self):
        if self.capture_process:
            self.capture_process.terminate()
        if self.traffic_process:
            self.traffic_process.terminate()

    def run(self):
        try:
            print("[+] Starting automated network analysis...")
            os.makedirs('analysis_output', exist_ok=True)

            self.start_traffic_generation()
            pcap_file = self.start_capture()
            self.wait_for_completion()
            self.cleanup()

            csv_file = self.process_data(pcap_file)
            self.generate_report(pcap_file, csv_file)

            print("[+] Analysis complete.")

        except KeyboardInterrupt:
            print("\nInterrupted by user")
        finally:
            self.cleanup()

if __name__ == "__main__":
    pipeline = NetworkAnalysisPipeline(duration=60)
    pipeline.run()
