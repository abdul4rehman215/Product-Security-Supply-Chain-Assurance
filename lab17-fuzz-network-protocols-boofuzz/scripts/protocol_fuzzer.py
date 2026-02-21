#!/usr/bin/env python3

import logging
from datetime import datetime
from pathlib import Path

from boofuzz import (
    s_initialize,
    s_string,
    s_delim,
    s_get,
)
from boofuzz_config import BoofuzzConfig


class ProtocolFuzzer:
    """Fuzzer for custom protocol"""

    def __init__(self):
        """
        Initialize fuzzer with configuration.
        """
        self.config = BoofuzzConfig(target_host="127.0.0.1", target_port=8080)
        self.config.setup_logging("fuzzing.log")
        logging.info("ProtocolFuzzer initialized.")

    def define_hello_message(self):
        s_initialize("hello_message")
        s_string("HELLO", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("client1", fuzzable=True, name="client_id")
        s_delim("\n", fuzzable=False)

    def define_get_message(self):
        s_initialize("get_message")
        s_string("GET", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("/resource", fuzzable=True, name="resource")
        s_delim("\n", fuzzable=False)

    def define_set_message(self):
        s_initialize("set_message")
        s_string("SET", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("key", fuzzable=True, name="key")
        s_delim(" ", fuzzable=False)
        s_string("value", fuzzable=True, name="value")
        s_delim("\n", fuzzable=False)

    def run_fuzzing_campaign(self):
        logging.info("Starting fuzzing campaign...")
        session = self.config.create_session()

        self.define_hello_message()
        self.define_get_message()
        self.define_set_message()

        session.connect(s_get("hello_message"))
        session.connect(s_get("hello_message"), s_get("get_message"))
        session.connect(s_get("hello_message"), s_get("set_message"))

        session.fuzz()
        self.generate_summary_report(session)
        logging.info("Fuzzing campaign completed.")

    def generate_summary_report(self, session):
        report_dir = Path(".")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = report_dir / f"fuzzing_summary_{timestamp}.txt"

        total_cases = getattr(session, "num_cases", None)
        crash_count = 0

        with open(report_file, "w", encoding="utf-8") as f:
            f.write("=== Boofuzz Fuzzing Summary Report ===\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Target: {self.config.target_host}:{self.config.target_port}\n\n")
            f.write(f"Estimated Test Cases Executed: {total_cases}\n")
            f.write(f"Crashes Detected (server-side): {crash_count}\n\n")
            f.write("Notes:\n")
            f.write("- This simple demo server may not crash easily.\n")
            f.write("- Check fuzzing.log for detailed execution logs.\n")

        logging.info(f"Summary report written to: {report_file}")


if __name__ == "__main__":
    fuzzer = ProtocolFuzzer()
    fuzzer.run_fuzzing_campaign()
