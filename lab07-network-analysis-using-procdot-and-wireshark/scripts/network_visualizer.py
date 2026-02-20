#!/usr/bin/env python3
# File: network_visualizer.py

import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx
from collections import defaultdict

class NetworkVisualizer:

    def __init__(self, csv_file):
        self.df = pd.read_csv(csv_file)
        self.G = nx.DiGraph()

    def create_network_graph(self):
        edge_counts = defaultdict(int)

        for _, row in self.df.iterrows():
            src = row['Source_IP']
            dst = row['Dest_IP']
            edge_counts[(src, dst)] += 1

        for (src, dst), weight in edge_counts.items():
            self.G.add_edge(src, dst, weight=weight)

    def visualize_flows(self, output_file='network_flows.png'):
        plt.figure(figsize=(15, 10))
        pos = nx.spring_layout(self.G, k=0.5)

        weights = [self.G[u][v]['weight'] for u, v in self.G.edges()]
        nx.draw(self.G, pos, with_labels=True,
                node_color='lightblue',
                node_size=1500,
                edge_color='gray',
                width=[w * 0.1 for w in weights])

        plt.title("Network Flow Visualization")
        plt.savefig(output_file)
        print(f"[+] Network visualization saved to {output_file}")

    def generate_statistics(self):
        print("\n=== Network Traffic Statistics ===")
        print(f"Total Packets: {len(self.df)}")

        print("\nProtocol Distribution:")
        print(self.df['Protocol'].value_counts())

        print("\nTop 10 Source IPs:")
        print(self.df['Source_IP'].value_counts().head(10))

        print("\nTop 10 Destination IPs:")
        print(self.df['Dest_IP'].value_counts().head(10))

        print("\nTop Destination Ports:")
        print(self.df['Dest_Port'].value_counts().head(10))

    def detect_anomalies(self):
        print("\n=== Anomaly Detection ===")

        threshold = self.df['Source_IP'].value_counts().mean() * 3

        high_volume = self.df['Source_IP'].value_counts()
        suspicious = high_volume[high_volume > threshold]

        if not suspicious.empty:
            print("High-volume IPs detected:")
            print(suspicious)
        else:
            print("No significant anomalies detected.")

def main():
    visualizer = NetworkVisualizer('network_data.csv')
    visualizer.create_network_graph()
    visualizer.visualize_flows()
    visualizer.generate_statistics()
    visualizer.detect_anomalies()

if __name__ == "__main__":
    main()
