import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QGuiApplication, QPalette

ACCENT = "#3b82f6"

DARK = {
    "bg": "#17181c", "surface": "#1f2026", "surface2": "#272830", "border": "#30323b",
    "text": "#e7e8ec", "muted": "#8b8d98", "hover": "#2b2d36", "select": "#2a3b5c",
    "danger": "#f87171", "warn": "#fbbf24", "ok": "#4ade80", "track": "#30323b",
}
LIGHT = {
    "bg": "#f4f5f7", "surface": "#ffffff", "surface2": "#f0f1f4", "border": "#dfe1e6",
    "text": "#1f2328", "muted": "#6b6f7b", "hover": "#eceef2", "select": "#dbe7fd",
    "danger": "#dc2626", "warn": "#b45309", "ok": "#16a34a", "track": "#e4e6eb",
}

current = dict(DARK)


def is_dark(mode):
    if mode == "dark":
        return True
    if mode == "light":
        return False
    return QGuiApplication.styleHints().colorScheme() != Qt.ColorScheme.Light


def apply(app, mode):
    c = DARK if is_dark(mode) else LIGHT
    current.clear()
    current.update(c)
    app.setStyle("Fusion")
    pal = QPalette()
    for role, key in [
        (QPalette.Window, "bg"), (QPalette.Base, "surface"), (QPalette.AlternateBase, "surface2"),
        (QPalette.Button, "surface"), (QPalette.Text, "text"), (QPalette.WindowText, "text"),
        (QPalette.ButtonText, "text"), (QPalette.ToolTipBase, "surface2"), (QPalette.ToolTipText, "text"),
        (QPalette.PlaceholderText, "muted"), (QPalette.Mid, "border"),
    ]:
        pal.setColor(role, QColor(c[key]))
    pal.setColor(QPalette.Highlight, QColor(c["select"]))
    pal.setColor(QPalette.HighlightedText, QColor(c["text"]))
    pal.setColor(QPalette.Link, QColor(ACCENT))
    pal.setColor(QPalette.Disabled, QPalette.Text, QColor(c["muted"]))
    pal.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(c["muted"]))
    pal.setColor(QPalette.Disabled, QPalette.WindowText, QColor(c["muted"]))
    app.setPalette(pal)
    check, partial = _indicator_images()
    app.setStyleSheet(QSS.format(accent=ACCENT, check=check, partial=partial, **c))


def _indicator_images():
    """QSS умеет брать картинки только из файлов — рисуем галочку один раз в папку данных."""
    from PySide6.QtCore import QPointF
    from PySide6.QtGui import QPainter, QPen, QPixmap

    from ..config import DATA_DIR
    os.makedirs(DATA_DIR, exist_ok=True)
    paths = []
    for name, points in (("check", [(3.5, 8.5), (6.5, 11.5), (12.5, 4.5)]), ("partial", [(4, 8), (12, 8)])):
        path = os.path.join(DATA_DIR, f"ui_{name}.png")
        if not os.path.exists(path):
            pm = QPixmap(32, 32)
            pm.fill(Qt.transparent)
            p = QPainter(pm)
            p.setRenderHint(QPainter.Antialiasing)
            p.scale(2, 2)
            p.setPen(QPen(QColor("white"), 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
            for a, b in zip(points, points[1:]):
                p.drawLine(QPointF(*a), QPointF(*b))
            p.end()
            pm.save(path, "PNG")
        paths.append(path.replace("\\", "/"))
    return paths


QSS = """
* {{ font-family: "Segoe UI Variable Text", "Segoe UI"; font-size: 10pt; }}
QMainWindow, QDialog {{ background: {bg}; }}
QToolTip {{ background: {surface2}; color: {text}; border: 1px solid {border}; padding: 4px 6px; }}

#Sidebar {{ background: {surface}; border-right: 1px solid {border}; }}
#Sidebar QListWidget {{ background: transparent; border: none; outline: none; }}
#Sidebar QListWidget::item {{ padding: 7px 10px; margin: 1px 8px; border-radius: 6px; color: {text}; }}
#Sidebar QListWidget::item:hover {{ background: {hover}; }}
#Sidebar QListWidget::item:selected {{ background: {select}; color: {text}; }}
#SidebarCaption {{ color: {muted}; font-size: 8pt; font-weight: 600; padding: 14px 18px 4px 18px; }}
#Brand {{ font-size: 13pt; font-weight: 600; padding: 16px 18px 6px 18px; }}

#SettingsNav {{ padding: 6px; }}
#SettingsNav::item {{ padding: 8px 10px; border-radius: 6px; }}
#SettingsNav::item:hover {{ background: {hover}; }}
#SettingsNav::item:selected {{ background: {select}; color: {text}; }}

#Toolbar {{ background: {bg}; border-bottom: 1px solid {border}; }}
QToolButton {{ background: transparent; border: none; border-radius: 6px; padding: 6px 8px; color: {text}; }}
QToolButton:hover {{ background: {hover}; }}
QToolButton:pressed, QToolButton:checked {{ background: {select}; }}

QPushButton {{ background: {surface2}; border: 1px solid {border}; border-radius: 6px; padding: 6px 14px; color: {text}; }}
QPushButton:hover {{ background: {hover}; }}
QPushButton:disabled {{ color: {muted}; }}
QPushButton[primary="true"] {{ background: {accent}; border-color: {accent}; color: white; font-weight: 600; }}
QPushButton[primary="true"]:hover {{ background: #2f6fde; }}

QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox, QTimeEdit, QPlainTextEdit {{
    background: {surface}; border: 1px solid {border}; border-radius: 6px; padding: 5px 8px; color: {text};
    selection-background-color: {accent}; selection-color: white;
}}
QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus, QTimeEdit:focus, QPlainTextEdit:focus {{ border-color: {accent}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{ background: {surface}; border: 1px solid {border}; selection-background-color: {select}; }}

QTableView, QTreeView, QTreeWidget, QTableWidget, QListWidget {{
    background: {surface}; border: 1px solid {border}; border-radius: 8px; gridline-color: transparent;
    alternate-background-color: {surface}; outline: none;
}}
QTableView::item, QTreeView::item {{ padding: 4px 6px; border: none; }}
QTableView::item:hover, QTreeView::item:hover {{ background: {hover}; }}
QTableView::item:selected, QTreeView::item:selected {{ background: {select}; color: {text}; }}
QHeaderView {{ background: transparent; }}
QHeaderView::section {{
    background: {surface}; color: {muted}; border: none; border-bottom: 1px solid {border};
    padding: 6px 8px; font-weight: 600; font-size: 9pt;
}}
QTableCornerButton::section {{ background: {surface}; border: none; }}

QTabWidget::pane {{ border: 1px solid {border}; border-radius: 8px; top: -1px; background: {surface}; }}
QTabBar::tab {{ background: transparent; color: {muted}; padding: 7px 14px; border: none; border-bottom: 2px solid transparent; }}
QTabBar::tab:selected {{ color: {text}; border-bottom: 2px solid {accent}; }}
QTabBar::tab:hover {{ color: {text}; }}

QSplitter::handle {{ background: transparent; }}
QStatusBar {{ background: {surface}; border-top: 1px solid {border}; color: {muted}; }}
QStatusBar QLabel {{ color: {muted}; padding: 0 8px; }}
QMenu {{ background: {surface}; border: 1px solid {border}; border-radius: 8px; padding: 4px; }}
QMenu::item {{ padding: 6px 22px 6px 12px; border-radius: 5px; }}
QMenu::item:selected {{ background: {hover}; }}
QMenu::separator {{ height: 1px; background: {border}; margin: 4px 8px; }}
QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator, QTreeView::indicator, QTableView::indicator, QGroupBox::indicator {{
    width: 15px; height: 15px; border: 1px solid {muted}; border-radius: 4px; background: {surface};
}}
QCheckBox::indicator:hover, QTreeView::indicator:hover {{ border-color: {accent}; }}
QCheckBox::indicator:checked, QTreeView::indicator:checked, QTableView::indicator:checked {{
    background: {accent}; border-color: {accent}; image: url({check});
}}
QTreeView::indicator:indeterminate {{ background: {accent}; border-color: {accent}; image: url({partial}); }}
QGroupBox {{ border: 1px solid {border}; border-radius: 8px; margin-top: 14px; padding: 12px 10px 8px 10px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; color: {muted}; font-weight: 600; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {border}; border-radius: 4px; min-height: 30px; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {border}; border-radius: 4px; min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

#Banner {{ border-radius: 8px; padding: 10px 12px; }}
#Banner[kind="warn"] {{ background: rgba(251,191,36,0.13); border: 1px solid rgba(251,191,36,0.45); }}
#Banner[kind="danger"] {{ background: rgba(248,113,113,0.13); border: 1px solid rgba(248,113,113,0.5); }}
#Banner[kind="info"] {{ background: rgba(59,130,246,0.12); border: 1px solid rgba(59,130,246,0.4); }}
#Muted {{ color: {muted}; }}
#DropZone {{ border: 2px dashed {border}; border-radius: 10px; background: {surface}; }}
#DropZone:hover {{ border-color: {accent}; }}
#Title {{ font-size: 12pt; font-weight: 600; }}
#Empty {{ color: {muted}; font-size: 11pt; }}
"""
