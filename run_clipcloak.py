"""PyInstaller entry point for the main application."""

import sys

from clipcloak.cli import main

if __name__ == "__main__":
    sys.exit(main())
