import os
import subprocess
import sys

_UNITS = ["Б", "КБ", "МБ", "ГБ", "ТБ"]


def fmt_size(n):
    n = float(n or 0)
    for unit in _UNITS:
        if abs(n) < 1024 or unit == _UNITS[-1]:
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024


def fmt_speed(n):
    return f"{fmt_size(n)}/с" if n and n > 0 else ""


def fmt_eta(seconds):
    if seconds is None or seconds < 0:
        return "∞"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} с"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m} мин {s} с"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h} ч {m} мин"
    d, h = divmod(h, 24)
    return f"{d} д {h} ч" if d < 100 else "∞"


def open_path(path):
    if sys.platform == "win32":
        os.startfile(path)
    else:
        subprocess.Popen(["xdg-open", path])


def reveal_in_explorer(path):
    if sys.platform == "win32" and os.path.exists(path):
        subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
    else:
        open_path(os.path.dirname(path) if os.path.isfile(path) else path)
