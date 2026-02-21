#!/usr/bin/env python3

import sys
import boofuzz
from boofuzz import Session, Target, TCPSocketConnection


def verify_installation():
    """
    Verify Boofuzz installation and display version.
    """

    try:
        print("Boofuzz successfully imported.")
        print("Boofuzz version:", boofuzz.__version__)

        # Test basic Session creation
        connection = TCPSocketConnection("127.0.0.1", 1)
        target = Target(connection=connection)
        session = Session(target=target)

        print("Session object created successfully.")
        return True

    except Exception as e:
        print("Verification failed:", str(e))
        return False


if __name__ == "__main__":
    success = verify_installation()
    sys.exit(0 if success else 1)
