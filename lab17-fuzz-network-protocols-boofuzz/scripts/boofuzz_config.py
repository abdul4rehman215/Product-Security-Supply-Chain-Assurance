#!/usr/bin/env python3

import logging
from boofuzz import Session, Target, TCPSocketConnection


class BoofuzzConfig:
    """Configuration manager for Boofuzz sessions"""

    def __init__(self, target_host="127.0.0.1", target_port=8080):
        """
        Initialize configuration with target details.
        """
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = 5.0
        self.crash_threshold = 3
        self.sleep_time = 0.1

    def setup_logging(self, log_file="fuzzing.log"):
        """
        Configure logging for fuzzing session.
        """
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)

        file_handler = logging.FileHandler(log_file)
        console_handler = logging.StreamHandler()

        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s"
        )

        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    def create_session(self):
        """
        Create and return a configured Boofuzz session.
        """
        connection = TCPSocketConnection(
            self.target_host,
            self.target_port
        )

        target = Target(connection=connection)

        session = Session(
            target=target,
            sleep_time=self.sleep_time
        )

        return session
