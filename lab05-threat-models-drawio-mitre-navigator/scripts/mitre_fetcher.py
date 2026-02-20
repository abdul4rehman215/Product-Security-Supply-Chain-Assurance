#!/usr/bin/env python3
"""
MITRE ATT&CK Data Fetcher
Fetches and processes MITRE ATT&CK framework data
"""

import requests
import pandas as pd
import json

class MitreAttackFetcher:
    def __init__(self):
        self.base_url = "https://raw.githubusercontent.com/mitre/cti/master"
        self.enterprise_url = f"{self.base_url}/enterprise-attack/enterprise-attack.json"

    def fetch_enterprise_data(self):
        """
        Fetch MITRE ATT&CK Enterprise data from GitHub

        Returns:
        dict: JSON data containing MITRE ATT&CK framework
        """
        try:
            resp = requests.get(self.enterprise_url, timeout=60)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Failed to fetch MITRE ATT&CK data: {e}")

    def extract_techniques(self, data):
        """
        Extract attack techniques from MITRE data

        Args:
        data: Raw MITRE ATT&CK JSON data

        Returns:
        list: List of technique dictionaries with id, name, tactics, platforms
        """
        techniques = []

        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue

            if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
                continue

            name = obj.get("name", "")
            stix_id = obj.get("id", "")

            external_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
                    if "external_id" in ref:
                        external_id = ref["external_id"]
                        break

            tactics = []
            for kc in obj.get("kill_chain_phases", []):
                phase = kc.get("phase_name")
                if phase:
                    tactics.append(phase)

            platforms = obj.get("x_mitre_platforms", [])
            if platforms is None:
                platforms = []

            desc = obj.get("description", "")
            if desc is None:
                desc = ""

            techniques.append({
                "technique_id": external_id if external_id else "",
                "stix_id": stix_id,
                "name": name,
                "tactics": tactics,
                "platforms": platforms,
                "description": desc
            })

        return techniques

    def save_to_csv(self, techniques, filename='mitre_techniques.csv'):
        """
        Save techniques to CSV file
        """
        df = pd.DataFrame(techniques)

        if "tactics" in df.columns:
            df["tactics"] = df["tactics"].apply(lambda x: ", ".join(x) if isinstance(x, list) else str(x))
        if "platforms" in df.columns:
            df["platforms"] = df["platforms"].apply(lambda x: ", ".join(x) if isinstance(x, list) else str(x))

        df.to_csv(filename, index=False)
        return df

def main():
    fetcher = MitreAttackFetcher()

    data = fetcher.fetch_enterprise_data()
    techniques = fetcher.extract_techniques(data)
    df = fetcher.save_to_csv(techniques, filename="mitre_techniques.csv")

    total = len(df)
    with_ids = (df["technique_id"] != "").sum() if "technique_id" in df.columns else 0

    print("[+] MITRE ATT&CK Enterprise data fetched successfully")
    print(f"[+] Techniques extracted: {total}")
    print(f"[+] Techniques with external IDs: {with_ids}")
    print("[+] Saved to: mitre_techniques.csv")

if __name__ == "__main__":
    main()
