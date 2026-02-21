#!/usr/bin/env python3
import json


def generate_protocol_documentation(analysis_results):
    """
    Generate protocol specification document.

    Document field structure and sizes
    List message types and meanings
    Describe checksum algorithm
    Note protocol version information
    Save as JSON file
    """
    spec = {
        "protocol_name": "Custom Protocol",
        "version": "1.0",
        "format": "[MAGIC(4)][VERSION(1)][TYPE(1)][LENGTH(2)][DATA][CHECKSUM(1)]",
        "fields": [
            {
                "name": "MAGIC",
                "size_bytes": 4,
                "offset": 0,
                "description": "Protocol identifier. Expected value: 'CPRO' (0x43 0x50 0x52 0x4f)."
            },
            {
                "name": "VERSION",
                "size_bytes": 1,
                "offset": 4,
                "description": "Protocol version. Observed value: 1."
            },
            {
                "name": "TYPE",
                "size_bytes": 1,
                "offset": 5,
                "description": "Message type code."
            },
            {
                "name": "LENGTH",
                "size_bytes": 2,
                "offset": 6,
                "description": "Big-endian unsigned length of DATA field."
            },
            {
                "name": "DATA",
                "size_bytes": "variable",
                "offset": 8,
                "description": "Payload data of LENGTH bytes. Observed plaintext messages."
            },
            {
                "name": "CHECKSUM",
                "size_bytes": 1,
                "offset": "8 + LENGTH",
                "description": "Integrity check value: sum(DATA bytes) % 256."
            }
        ],
        "message_types": {
            "1": "WELCOME - greeting and banner",
            "2": "STATUS - server status info",
            "3": "DATA - data payload (observed plaintext 'flag' keyword demo)"
        },
        "checksum_algorithm": "checksum = sum(DATA bytes) % 256",
        "security_notes": [
            "Payload is plaintext (no encryption) - susceptible to information disclosure.",
            "Integrity uses simple 1-byte checksum - weak against intentional tampering and collisions.",
            "Predictable magic bytes and fixed header - easy fingerprinting and replay.",
            "No authentication field present - unauthenticated messages can be crafted and injected."
        ],
        "analysis_summary": analysis_results
    }

    with open("protocol_spec.json", "w") as f:
        json.dump(spec, f, indent=2)

    return spec


if __name__ == "__main__":
    # Load dissector output if available
    try:
        with open("dissector_results.json", "r") as f:
            analysis_results = json.load(f)
    except Exception:
        analysis_results = {
            "note": "No dissector_results.json found; run protocol_dissector.py first"
        }

    spec = generate_protocol_documentation(analysis_results)
    print("[+] Saved protocol_spec.json")
