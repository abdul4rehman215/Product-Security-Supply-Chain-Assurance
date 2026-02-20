#!/usr/bin/env python3
# File: pcap_converter.py

import pyshark
import csv
import sys

def convert_pcap_to_csv(pcap_file, output_file):
    """
    Convert PCAP file to CSV format for analysis
    """

    try:
        cap = pyshark.FileCapture(pcap_file)

        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = [
                'Time',
                'Source_IP',
                'Dest_IP',
                'Source_Port',
                'Dest_Port',
                'Protocol',
                'Length'
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for packet in cap:
                try:
                    # Skip non-IP packets
                    if 'IP' not in packet:
                        continue

                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    protocol = packet.highest_layer
                    length = packet.length
                    timestamp = packet.sniff_time

                    src_port = ""
                    dst_port = ""

                    if 'TCP' in packet:
                        src_port = packet.tcp.srcport
                        dst_port = packet.tcp.dstport
                    elif 'UDP' in packet:
                        src_port = packet.udp.srcport
                        dst_port = packet.udp.dstport

                    writer.writerow({
                        'Time': timestamp,
                        'Source_IP': src_ip,
                        'Dest_IP': dst_ip,
                        'Source_Port': src_port,
                        'Dest_Port': dst_port,
                        'Protocol': protocol,
                        'Length': length
                    })

                except Exception:
                    # Skip malformed packets
                    continue

        cap.close()
        print(f"[+] CSV created: {output_file}")
        return True

    except Exception as e:
        print(f"Error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 pcap_converter.py <input.pcap> <output.csv>")
        sys.exit(1)

    convert_pcap_to_csv(sys.argv[1], sys.argv[2])
