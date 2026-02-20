#!/usr/bin/env python3
# File: create_procmon_log.py

import csv
import datetime
import random

def create_procmon_log(output_file='procmon_log.csv'):
    """
    Create a simulated Procmon-style process activity log
    for correlation with network traffic.
    """

    processes = ['python3', 'curl', 'firefox', 'product_scanner']
    operations = ['TCP Connect', 'TCP Disconnect', 'DNS Query']
    targets = [
        'httpbin.org:80',
        'api.security-scanner.com:443',
        'product-security.example.com:53'
    ]

    now = datetime.datetime.now()

    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['Time', 'Process', 'PID', 'Operation', 'Target', 'Result']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for i in range(random.randint(500, 1000)):
            timestamp = now + datetime.timedelta(seconds=i)
            process = random.choice(processes)
            pid = random.randint(1000, 5000)
            operation = random.choice(operations)
            target = random.choice(targets)
            result = random.choice(['SUCCESS', 'FAILED'])

            writer.writerow({
                'Time': timestamp,
                'Process': process,
                'PID': pid,
                'Operation': operation,
                'Target': target,
                'Result': result
            })

    print(f"[+] Process monitor log created: {output_file}")

if __name__ == "__main__":
    create_procmon_log()
