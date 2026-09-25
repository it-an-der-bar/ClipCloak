"""Central application identity.

Every user-visible name, the config directory, the IPC socket name and the
binary name are derived from the constants in this file. To rename the
application run ``python tools/rename_app.py <newname>`` which also renames the
Python package and updates CI/README references.
"""

APP_NAME = "clipcloak"          # technical name: binaries, config dir, IPC
APP_DISPLAY_NAME = "ClipCloak"  # name shown in the UI
APP_ORG = "it-an-der-bar"
APP_ID = "de.it-an-der-bar.clipcloak"
APP_URL = "https://github.com/it-an-der-bar/ClipCloak"   # project homepage
RELEASES_URL = APP_URL + "/releases" if APP_URL else ""
APP_LICENSE = "GPL-3.0-only"
NER_HELPER_NAME = APP_NAME + "-ner"
