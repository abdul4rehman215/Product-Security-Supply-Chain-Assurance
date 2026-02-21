import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import json
import os
from datetime import datetime


class TelemetryAnalyzer:
    """Automated telemetry data processing and reporting."""

    def __init__(self, data_path="../data/", output_path="../output/"):
        self.data_path = data_path
        self.output_path = output_path
        self.telemetry_df = None
        self.report = {}

        os.makedirs(self.output_path, exist_ok=True)

    def load_data(self):
        """Load telemetry data from CSV file."""
        try:
            csv_file = os.path.join(self.data_path, "product_telemetry.csv")
            self.telemetry_df = pd.read_csv(csv_file)

            self.telemetry_df["timestamp"] = pd.to_datetime(self.telemetry_df["timestamp"])

            # Drop duplicates and NA safely
            self.telemetry_df = self.telemetry_df.drop_duplicates().dropna()

            # Convert numeric columns safely
            numeric_cols = [
                "temperature_celsius",
                "cpu_usage_percent",
                "memory_usage_percent",
                "power_consumption_watts",
                "network_latency_ms",
                "error_count",
            ]
            for col in numeric_cols:
                self.telemetry_df[col] = pd.to_numeric(self.telemetry_df[col], errors="coerce")

            self.telemetry_df = self.telemetry_df.dropna(subset=numeric_cols)

            # Filter invalid values
            self.telemetry_df = self.telemetry_df[
                (self.telemetry_df["cpu_usage_percent"] >= 0) &
                (self.telemetry_df["cpu_usage_percent"] <= 100) &
                (self.telemetry_df["memory_usage_percent"] >= 0) &
                (self.telemetry_df["memory_usage_percent"] <= 100) &
                (self.telemetry_df["temperature_celsius"] > -50)
            ]

            return True
        except Exception as e:
            print("Error loading data:", str(e))
            return False

    def calculate_statistics(self):
        """Calculate summary statistics for the report."""
        df = self.telemetry_df

        self.report["total_records"] = int(df.shape[0])
        self.report["total_devices"] = int(df["device_id"].nunique())
        self.report["product_types"] = df["product_type"].unique().tolist()
        self.report["locations"] = df["location"].unique().tolist()

        min_ts = df["timestamp"].min()
        max_ts = df["timestamp"].max()

        self.report["date_range"] = {
            "start": str(min_ts),
            "end": str(max_ts)
        }

        product_stats = df.groupby("product_type").agg({
            "temperature_celsius": "mean",
            "cpu_usage_percent": "mean",
            "memory_usage_percent": "mean",
            "power_consumption_watts": "mean",
            "network_latency_ms": "mean",
            "error_count": "mean"
        }).round(2)

        self.report["metrics_by_product_type"] = product_stats.to_dict()

        top_error_devices = df.groupby("device_id")["error_count"].sum().sort_values(ascending=False).head(10)
        self.report["top_10_devices_by_total_errors"] = top_error_devices.to_dict()

        top_power_devices = df.groupby("device_id")["power_consumption_watts"].mean().sort_values(ascending=False).head(10)
        self.report["top_10_devices_by_avg_power_consumption"] = top_power_devices.round(2).to_dict()

    def detect_temperature_anomalies(self, std_threshold=2):
        df = self.telemetry_df
        mean_temp = df["temperature_celsius"].mean()
        std_temp = df["temperature_celsius"].std()

        upper_bound = mean_temp + (std_threshold * std_temp)
        lower_bound = mean_temp - (std_threshold * std_temp)

        anomalies = df[
            (df["temperature_celsius"] > upper_bound) |
            (df["temperature_celsius"] < lower_bound)
        ]
        return anomalies

    def detect_performance_anomalies(self, cpu_threshold=80, memory_threshold=90):
        df = self.telemetry_df
        anomalies = df[
            (df["cpu_usage_percent"] > cpu_threshold) |
            (df["memory_usage_percent"] > memory_threshold)
        ]
        return anomalies

    def detect_power_anomalies(self, std_threshold=2):
        df = self.telemetry_df
        mean_power = df["power_consumption_watts"].mean()
        std_power = df["power_consumption_watts"].std()

        upper_bound = mean_power + (std_threshold * std_power)
        anomalies = df[df["power_consumption_watts"] > upper_bound]
        return anomalies

    def detect_all_anomalies(self):
        """Detect all types of anomalies."""
        temp_anom = self.detect_temperature_anomalies()
        perf_anom = self.detect_performance_anomalies()
        power_anom = self.detect_power_anomalies()

        self.report["anomalies"] = {
            "temperature_anomalies_count": int(len(temp_anom)),
            "performance_anomalies_count": int(len(perf_anom)),
            "power_anomalies_count": int(len(power_anom)),
        }

        self.report["anomalies_samples"] = {
            "temperature_anomalies_sample": temp_anom.head(5).to_dict(orient="records"),
            "performance_anomalies_sample": perf_anom.head(5).to_dict(orient="records"),
            "power_anomalies_sample": power_anom.head(5).to_dict(orient="records"),
        }

    def generate_visualizations(self):
        """Generate all analysis visualizations."""
        df = self.telemetry_df.copy()

        # Distribution plots
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))

        product_counts = df["product_type"].value_counts()
        axes[0, 0].pie(product_counts, labels=product_counts.index, autopct="%1.1f%%")
        axes[0, 0].set_title("Product Type Distribution")

        axes[0, 1].hist(df["temperature_celsius"], bins=30)
        axes[0, 1].set_title("Temperature Distribution")
        axes[0, 1].set_xlabel("Temperature (°C)")

        axes[1, 0].scatter(df["cpu_usage_percent"], df["memory_usage_percent"], alpha=0.5)
        axes[1, 0].set_title("CPU vs Memory Usage")
        axes[1, 0].set_xlabel("CPU Usage (%)")
        axes[1, 0].set_ylabel("Memory Usage (%)")

        df.boxplot(column="power_consumption_watts", by="product_type", ax=axes[1, 1])
        axes[1, 1].set_title("Power Consumption by Product Type")
        axes[1, 1].set_xlabel("Product Type")
        axes[1, 1].set_ylabel("Power (Watts)")

        plt.suptitle("")
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_path, "distribution_analysis.png"), dpi=300)
        plt.close()

        # Time series plots
        df_ts = df.set_index("timestamp").sort_index()

        daily_temp = df_ts["temperature_celsius"].resample("D").mean()
        daily_cpu = df_ts["cpu_usage_percent"].resample("D").mean()
        hourly_power = df_ts["power_consumption_watts"].resample("H").mean()

        fig, axes = plt.subplots(3, 1, figsize=(14, 10))

        daily_temp.plot(ax=axes[0])
        axes[0].set_title("Daily Average Temperature")
        axes[0].set_ylabel("Temperature (°C)")
        axes[0].grid(True)

        daily_cpu.plot(ax=axes[1])
        axes[1].set_title("Daily Average CPU Usage")
        axes[1].set_ylabel("CPU Usage (%)")
        axes[1].grid(True)

        hourly_power.groupby(hourly_power.index.hour).mean().plot(ax=axes[2], kind="bar")
        axes[2].set_title("Hourly Average Power Consumption (Aggregated by Hour)")
        axes[2].set_xlabel("Hour of Day")
        axes[2].set_ylabel("Power (Watts)")
        axes[2].grid(True)

        plt.tight_layout()
        plt.savefig(os.path.join(self.output_path, "time_series_analysis.png"), dpi=300)
        plt.close()

        # Anomaly plots (temperature anomalies)
        temp_anom = self.detect_temperature_anomalies()
        normal = df[~df.index.isin(temp_anom.index)]

        plt.figure(figsize=(12, 6))
        plt.scatter(normal["timestamp"], normal["temperature_celsius"], alpha=0.4, label="Normal")
        plt.scatter(temp_anom["timestamp"], temp_anom["temperature_celsius"], alpha=0.8, label="Anomaly")
        plt.title("Temperature Anomalies Over Time")
        plt.xlabel("Timestamp")
        plt.ylabel("Temperature (°C)")
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_path, "anomaly_detection.png"), dpi=300)
        plt.close()

        # Correlation heatmap (matplotlib-only to avoid seaborn dependency in automation)
        numeric_cols = df.select_dtypes(include=[np.number])
        corr = numeric_cols.corr()

        plt.figure(figsize=(10, 8))
        plt.imshow(corr, aspect="auto")
        plt.colorbar()
        plt.xticks(range(len(corr.columns)), corr.columns, rotation=45, ha="right")
        plt.yticks(range(len(corr.index)), corr.index)
        plt.title("Correlation Matrix Heatmap")
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_path, "correlation_heatmap.png"), dpi=300)
        plt.close()

    def save_report(self):
        """Save analysis report to JSON file."""
        self.report["report_generated_at"] = datetime.now().isoformat()

        report_file = os.path.join(self.output_path, "analysis_report.json")
        with open(report_file, "w") as f:
            json.dump(self.report, f, indent=4, default=str)

        print("\nReport saved to:", report_file)
        print("\n--- Report Summary ---")
        print("Total records:", self.report.get("total_records"))
        print("Total devices:", self.report.get("total_devices"))
        print("Anomalies:", self.report.get("anomalies"))

    def run_full_analysis(self):
        """Execute complete analysis pipeline."""
        print("Starting automated telemetry analysis...")

        if not self.load_data():
            print("Failed to load data. Exiting.")
            return

        self.calculate_statistics()
        self.detect_all_anomalies()
        self.generate_visualizations()
        self.save_report()

        print("Analysis complete!")


if __name__ == "__main__":
    analyzer = TelemetryAnalyzer()
    analyzer.run_full_analysis()
