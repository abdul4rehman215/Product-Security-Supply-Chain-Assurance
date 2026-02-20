#!/usr/bin/env python3
import os
import subprocess
import sys
import argparse
from pathlib import Path

class APKDecompiler:
    def __init__(self, apk_path, output_dir):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.decompiled_dir = os.path.join(self.output_dir, "apktool_decompiled")

    def decompile_apk(self):
        """
        Decompile APK using apktool

        - Implement subprocess call to apktool
        - Handle errors and return status
        - Print success/failure messages
        """
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

        if os.path.exists(self.decompiled_dir):
            print(f"[i] Output directory already exists: {self.decompiled_dir}")
            print("[i] Re-decompiling with force (-f) to ensure fresh output...")

        cmd = ["apktool", "d", "-f", self.apk_path, "-o", self.decompiled_dir]
        print(f"[+] Running: {' '.join(cmd)}")

        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if p.returncode == 0:
                print(f"[+] Decompilation successful: {self.decompiled_dir}")
                return True
            else:
                print("[-] Decompilation failed.")
                if p.stdout.strip():
                    print("[apktool stdout]")
                    print(p.stdout)
                if p.stderr.strip():
                    print("[apktool stderr]")
                    print(p.stderr)
                return False
        except FileNotFoundError:
            print("[-] apktool not found. Install it first (e.g., sudo apt install apktool).")
            return False
        except Exception as e:
            print(f"[-] Unexpected error running apktool: {e}")
            return False

    def analyze_manifest(self):
        """
        Analyze AndroidManifest.xml for security issues
        """
        manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            print(f"[-] Manifest not found: {manifest_path}")
            print("[i] Make sure decompilation succeeded.")
            return False

        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            manifest = f.read()

        print("\n========== Manifest Analysis ==========")

        dangerous = [
            "WRITE_EXTERNAL_STORAGE",
            "READ_EXTERNAL_STORAGE",
            "CAMERA",
            "RECORD_AUDIO",
            "ACCESS_FINE_LOCATION",
            "READ_CONTACTS",
            "SEND_SMS",
        ]

        found_perms = []
        for perm in dangerous:
            if perm in manifest:
                found_perms.append(perm)

        if found_perms:
            print("[!] Dangerous permissions found:")
            for p in found_perms:
                print(f"    - {p}")
        else:
            print("[+] No listed dangerous permissions found (based on simple string match).")

        if "android:exported" in manifest:
            print("[!] Found android:exported attributes. Review exported components carefully.")
        else:
            print("[+] No android:exported attributes found.")

        if "android:debuggable=\"true\"" in manifest or "debuggable=\"true\"" in manifest:
            print("[!] Debuggable mode appears ENABLED in manifest.")
        else:
            print("[+] Debuggable mode not explicitly enabled in manifest.")

        if "android:allowBackup=\"true\"" in manifest:
            print("[!] allowBackup is enabled (android:allowBackup=\"true\"). Consider disabling for sensitive apps.")
        elif "android:allowBackup" in manifest:
            print("[i] allowBackup is present but not obviously true. Review value.")
        else:
            print("[i] allowBackup not explicitly set.")

        return True

    def find_hardcoded_strings(self):
        """
        Search for hardcoded sensitive strings in resources
        """
        print("\n========== Hardcoded String Search (resources) ==========")

        res_dir = os.path.join(self.decompiled_dir, "res")
        if not os.path.isdir(res_dir):
            print(f"[-] Resource directory not found: {res_dir}")
            return False

        patterns = ["password", "key", "token", "secret", "api"]
        hits = []

        for root, dirs, files in os.walk(res_dir):
            if "values" not in os.path.basename(root):
                continue
            for fn in files:
                if not fn.endswith(".xml"):
                    continue
                fp = os.path.join(root, fn)
                try:
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().lower()
                    for pat in patterns:
                        if pat in content:
                            hits.append(fp)
                            break
                except Exception:
                    continue

        if hits:
            print("[!] Potential sensitive patterns found in these resource files:")
            for h in sorted(set(hits)):
                print(f"    - {h}")
        else:
            print("[+] No obvious sensitive patterns found in res/values*.xml files.")

        return True


def main():
    parser = argparse.ArgumentParser(description='APK Decompiler and Analyzer')
    parser.add_argument('apk_path', help='Path to APK file')
    parser.add_argument('-o', '--output', default='decompiled_apk', help='Output directory')

    args = parser.parse_args()

    if not os.path.isfile(args.apk_path):
        print(f"[-] APK not found: {args.apk_path}")
        sys.exit(1)

    dec = APKDecompiler(args.apk_path, args.output)

    try:
        ok = dec.decompile_apk()
        if not ok:
            sys.exit(2)

        dec.analyze_manifest()
        dec.find_hardcoded_strings()

        print("\n[+] Done.")
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(3)


if __name__ == "__main__":
    main()
