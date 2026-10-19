"""Вывод недоверенного текста (имена из торрентов, ответы серверов) без интерпретации HTML.

QLabel, QMessageBox и подсказки Qt сами угадывают HTML в строке, поэтому имя файла вида
«<b style=...>Проверено антивирусом</b>» могло бы подделать интерфейс."""
import html

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QMessageBox


def plain_label(text="", object_name=None, wrap=True):
    lbl = QLabel()
    lbl.setTextFormat(Qt.PlainText)
    lbl.setText(text)
    lbl.setWordWrap(wrap)
    if object_name:
        lbl.setObjectName(object_name)
    return lbl


def tip(text):
    """Подсказка, где текст показывается как есть."""
    return f"<span>{html.escape(str(text))}</span>"


def warn(parent, title, text):
    box = QMessageBox(QMessageBox.Warning, title, "", QMessageBox.Ok, parent)
    box.setTextFormat(Qt.PlainText)
    box.setText(text)
    box.exec()


def ask(parent, title, text, yes_text, no_text="Отмена"):
    box = QMessageBox(QMessageBox.Warning, title, "", QMessageBox.NoButton, parent)
    box.setTextFormat(Qt.PlainText)
    box.setText(text)
    yes = box.addButton(yes_text, QMessageBox.AcceptRole)
    no = box.addButton(no_text, QMessageBox.RejectRole)
    box.setDefaultButton(no)
    box.exec()
    return box.clickedButton() is yes
