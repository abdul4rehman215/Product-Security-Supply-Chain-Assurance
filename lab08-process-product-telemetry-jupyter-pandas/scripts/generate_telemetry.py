import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import os

def generate_telemetry_data():
    """
    Generate sample product telemetry data for IoT devices.
    Creates 5000 records with device metrics and anomalies.
    """
    np.random.seed(42)
    random.seed(42)

    # Define product types list
    product_types = ["SmartSensor", "EdgeGateway", "IndustrialCamera", "Thermostat"]

    # Define locations list
    locations = ["New York", "London", "Berlin", "Tokyo", "Sydney"]

    # Set date range (30 days)
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)

    telemetry_records = []

    for i in range(5000):

        timestamp = start_date + timedelta(
            seconds=random.randint(0, int((end_date - start_date).total_seconds()))
        )

        product_type = random.choice(product_types)
        location = random.choice(locations)
        device_id = f"{product_type[:3].upper()}-{random.randint(1000,9999)}"

        if product_type == "SmartSensor":
            temperature = np.random.normal(25, 5)
            power = np.random.normal(50, 10)
        elif product_type == "EdgeGateway":
            temperature = np.random.normal(40, 7)
            power = np.random.normal(120, 20)
        elif product_type == "IndustrialCamera":
            temperature = np.random.normal(35, 6)
            power = np.random.normal(90, 15)
        else:
            temperature = np.random.normal(22, 4)
            power = np.random.normal(40, 8)

        cpu_usage = np.random.normal(50, 15)
        memory_usage = np.random.normal(60, 20)
        network_latency = np.random.normal(30, 10)
        error_count = np.random.poisson(1)

        # Add 5% anomalies
        if random.random() < 0.05:
            temperature *= 1.8
            cpu_usage = min(100, cpu_usage * 1.5)
            memory_usage = min(100, memory_usage * 1.5)
            power *= 1.7
            error_count += random.randint(5, 20)

        record = {
            "timestamp": timestamp,
            "device_id": device_id,
            "product_type": product_type,
            "location": location,
            "temperature_celsius": round(temperature, 2),
            "cpu_usage_percent": round(cpu_usage, 2),
            "memory_usage_percent": round(memory_usage, 2),
            "power_consumption_watts": round(power, 2),
            "network_latency_ms": round(network_latency, 2),
            "error_count": error_count
        }

        telemetry_records.append(record)

    df = pd.DataFrame(telemetry_records)
    df.sort_values("timestamp", inplace=True)

    os.makedirs("data", exist_ok=True)
    df.to_csv("data/product_telemetry.csv", index=False)

    print("Generated telemetry data saved to data/product_telemetry.csv")

if __name__ == "__main__":
    generate_telemetry_data()
