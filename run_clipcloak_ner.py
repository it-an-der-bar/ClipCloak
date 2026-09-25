"""PyInstaller entry point for the optional NER helper (spaCy)."""

import sys

from clipcloak.ner_helper import main

if __name__ == "__main__":
    sys.exit(main())
