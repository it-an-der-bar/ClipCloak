"""Language menu (bilingual title so it can be found in any language)."""

from __future__ import annotations

from PySide6.QtGui import QAction, QActionGroup

from ..i18n import LANGUAGES

TITLE = "Sprache / Language"


def add_language_menu(parent, controller):
    """``parent`` is a QMenu or QMenuBar."""
    menu = parent.addMenu(TITLE)
    group = QActionGroup(menu)
    current = controller.cfg.get("general.language", "auto")
    for code, label in [("auto", "Automatisch / Automatic")] + list(LANGUAGES.items()):
        a = QAction(label, menu, checkable=True)
        a.setChecked(code == current)
        a.triggered.connect(lambda _=False, c=code: controller.set_language(c))
        group.addAction(a)
        menu.addAction(a)
    return menu
