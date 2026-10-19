"""Векторные иконки в стиле «контур», нарисованные QPainter (сетка 24×24)."""
import math

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap

ACCENT = "#3b82f6"
_cache = {}


def _lines(p, *segments):
    for seg in segments:
        path = QPainterPath(QPointF(*seg[0]))
        for pt in seg[1:]:
            path.lineTo(QPointF(*pt))
        p.drawPath(path)


def _draw(name, p):
    if name == "add":
        _lines(p, [(12, 5), (12, 19)], [(5, 12), (19, 12)])
    elif name == "link":
        p.save()
        p.translate(12, 12)
        p.rotate(-45)
        p.drawRoundedRect(QRectF(-9.5, -3.2, 10, 6.4), 3.2, 3.2)
        p.drawRoundedRect(QRectF(-0.5, -3.2, 10, 6.4), 3.2, 3.2)
        p.restore()
    elif name == "play":
        path = QPainterPath(QPointF(8, 5))
        path.lineTo(19, 12)
        path.lineTo(8, 19)
        path.closeSubpath()
        p.drawPath(path)
    elif name == "pause":
        p.drawRoundedRect(QRectF(7, 5, 3, 14), 1, 1)
        p.drawRoundedRect(QRectF(14, 5, 3, 14), 1, 1)
    elif name == "delete":
        _lines(p, [(4, 7), (20, 7)], [(9, 7), (9, 4), (15, 4), (15, 7)],
               [(6, 7), (7, 20), (17, 20), (18, 7)], [(10, 11), (10, 16)], [(14, 11), (14, 16)])
    elif name == "settings":
        p.drawEllipse(QPointF(12, 12), 3, 3)
        p.drawEllipse(QPointF(12, 12), 6.5, 6.5)
        for i in range(8):
            a = math.radians(i * 45)
            _lines(p, [(12 + 6.5 * math.cos(a), 12 + 6.5 * math.sin(a)),
                       (12 + 9.5 * math.cos(a), 12 + 9.5 * math.sin(a))])
    elif name == "folder":
        _lines(p, [(3, 6), (9, 6), (11, 8.5), (21, 8.5), (21, 19), (3, 19), (3, 6)])
    elif name == "search":
        p.drawEllipse(QPointF(10.5, 10.5), 6, 6)
        _lines(p, [(15, 15), (20, 20)])
    elif name == "down":
        _lines(p, [(12, 4), (12, 18)], [(6, 12), (12, 18), (18, 12)], [(5, 21), (19, 21)])
    elif name == "up":
        _lines(p, [(12, 20), (12, 6)], [(6, 12), (12, 6), (18, 12)], [(5, 3), (19, 3)])
    elif name == "all":
        for y in (6, 12, 18):
            _lines(p, [(9, y), (20, y)])
            p.drawEllipse(QPointF(4.5, y), 0.6, 0.6)
    elif name == "check":
        _lines(p, [(5, 12.5), (10, 17.5), (19, 7)])
    elif name == "error":
        p.drawEllipse(QPointF(12, 12), 9, 9)
        _lines(p, [(12, 7.5), (12, 13)], [(12, 16.4), (12, 16.6)])
    elif name == "speed":
        p.drawArc(QRectF(3, 5, 18, 18), 200 * 16, -220 * 16)
        _lines(p, [(12, 14), (16.5, 9)])
    elif name == "active":
        _lines(p, [(8, 4), (8, 19)], [(4, 15), (8, 19), (12, 15)],
               [(16, 20), (16, 5)], [(12, 9), (16, 5), (20, 9)])
    elif name == "shield":
        _lines(p, [(12, 3), (19, 6), (19, 11), (12, 21), (5, 11), (5, 6), (12, 3)])
    elif name == "copy":
        p.drawRoundedRect(QRectF(8, 8, 12, 12), 2, 2)
        _lines(p, [(5, 16), (4, 16), (4, 4), (16, 4), (16, 5)])
    elif name == "refresh":
        p.drawArc(QRectF(4, 4, 16, 16), 60 * 16, 270 * 16)
        _lines(p, [(16.5, 3), (16.5, 6.6), (13, 6.6)])
    elif name == "compress":
        _lines(p, [(12, 3), (12, 9)], [(9, 6.5), (12, 9.5), (15, 6.5)],
               [(12, 21), (12, 15)], [(9, 17.5), (12, 14.5), (15, 17.5)], [(4, 12), (20, 12)])
    elif name == "external":
        _lines(p, [(14, 4), (20, 4), (20, 10)], [(20, 4), (11, 13)],
               [(18, 14), (18, 20), (4, 20), (4, 6), (10, 6)])


_FILLED = {"play", "pause"}


def icon(name, color=None, size=48):
    color = color or "#8b8d98"
    key = (name, color, size)
    if key in _cache:
        return _cache[key]
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.scale(size / 24, size / 24)
    c = QColor(color)
    p.setPen(QPen(c, 2 if name not in _FILLED else 1.2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    p.setBrush(c if name in _FILLED else Qt.NoBrush)
    _draw(name, p)
    p.end()
    ic = QIcon(pm)
    _cache[key] = ic
    return ic


def app_pixmap(size=256):
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.scale(size / 24, size / 24)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor(ACCENT))
    p.drawRoundedRect(QRectF(1, 1, 22, 22), 6, 6)
    p.setPen(QPen(QColor("white"), 2.4, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    p.setBrush(Qt.NoBrush)
    _lines(p, [(12, 5.5), (12, 15.5)], [(7.5, 11.5), (12, 16), (16.5, 11.5)])
    # «волна» потока под стрелкой
    wave = QPainterPath(QPointF(6, 19))
    wave.cubicTo(8, 17.6, 10, 20.4, 12, 19)
    wave.cubicTo(14, 17.6, 16, 20.4, 18, 19)
    p.drawPath(wave)
    p.end()
    return pm


def app_icon():
    ic = QIcon()
    for s in (16, 24, 32, 48, 64, 128, 256):
        ic.addPixmap(app_pixmap(s))
    return ic
