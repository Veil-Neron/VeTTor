"""Интеграция с Windows: открытие .torrent и magnet-ссылок, автозапуск. Всё в HKCU."""
import os
import sys

if sys.platform == "win32":
    import ctypes
    import winreg

from .config import APP_NAME, APP_TITLE, ICON_PATH

PROGID_TORRENT = f"{APP_NAME}.torrent"
PROGID_MAGNET = f"{APP_NAME}.magnet"
CAPS = rf"Software\{APP_NAME}\Capabilities"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def _launcher():
    if getattr(sys, "frozen", False):  # собранный VeTTor.exe
        return f'"{sys.executable}"'
    exe = sys.executable
    pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if os.path.exists(pyw):
        exe = pyw
    script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "VeTTor.pyw")
    return f'"{exe}" "{script}"'


def _set(path, values):
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as k:
        for name, value in values.items():
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)


def _query(path):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as k:
            return winreg.QueryValue(k, None) or ""
    except OSError:
        return ""


def _delete_tree(path):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS) as k:
            while True:
                try:
                    sub = winreg.EnumKey(k, 0)
                except OSError:
                    break
                _delete_tree(path + "\\" + sub)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
    except FileNotFoundError:
        pass


def _notify():
    ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)


def set_associations(enable):
    if sys.platform != "win32":
        return
    cmd = _launcher() + ' "%1"'
    classes = r"Software\Classes"
    if enable:
        _set(rf"{classes}\{PROGID_TORRENT}", {"": "Торрент-файл"})
        _set(rf"{classes}\{PROGID_TORRENT}\DefaultIcon", {"": ICON_PATH})
        _set(rf"{classes}\{PROGID_TORRENT}\shell\open\command", {"": cmd})
        _set(rf"{classes}\{PROGID_MAGNET}", {"": "URL:Magnet", "URL Protocol": ""})
        _set(rf"{classes}\{PROGID_MAGNET}\DefaultIcon", {"": ICON_PATH})
        _set(rf"{classes}\{PROGID_MAGNET}\shell\open\command", {"": cmd})
        _set(rf"{classes}\.torrent", {"": PROGID_TORRENT})
        _set(rf"{classes}\.torrent\OpenWithProgids", {PROGID_TORRENT: ""})
        _set(rf"{classes}\magnet", {"": "URL:Magnet", "URL Protocol": ""})
        _set(rf"{classes}\magnet\shell\open\command", {"": cmd})
        _set(CAPS, {"ApplicationName": APP_TITLE,
                    "ApplicationDescription": "Торрент-клиент без рекламы"})
        _set(CAPS + r"\FileAssociations", {".torrent": PROGID_TORRENT})
        _set(CAPS + r"\URLAssociations", {"magnet": PROGID_MAGNET})
        _set(r"Software\RegisteredApplications", {APP_NAME: CAPS})
    else:
        _delete_tree(rf"{classes}\{PROGID_TORRENT}")
        _delete_tree(rf"{classes}\{PROGID_MAGNET}")
        _delete_tree(rf"Software\{APP_NAME}")
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"{classes}\.torrent\OpenWithProgids",
                                0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, PROGID_TORRENT)
        except FileNotFoundError:
            pass
        # Чужие обработчики не трогаем — удаляем только то, что указывает на нас.
        if _query(rf"{classes}\.torrent") == PROGID_TORRENT:
            _set(rf"{classes}\.torrent", {"": ""})
        if APP_NAME.lower() in _query(rf"{classes}\magnet\shell\open\command").lower():
            _delete_tree(rf"{classes}\magnet")
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\RegisteredApplications",
                                0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, APP_NAME)
        except FileNotFoundError:
            pass
    _notify()


def remove_legacy():
    """Убирает записи реестра старого имени программы («Поток» / Potok), если они были."""
    if sys.platform != "win32":
        return
    classes = r"Software\Classes"
    for path in (rf"{classes}\Potok.torrent", rf"{classes}\Potok.magnet", r"Software\Potok"):
        _delete_tree(path)
    if _query(rf"{classes}\.torrent") == "Potok.torrent":
        _set(rf"{classes}\.torrent", {"": ""})
    if "Potok" in _query(rf"{classes}\magnet\shell\open\command"):
        _delete_tree(rf"{classes}\magnet")
    for key, name in ((rf"{classes}\.torrent\OpenWithProgids", "Potok.torrent"),
                      (r"Software\RegisteredApplications", "Potok"), (RUN_KEY, "Potok")):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, name)
        except FileNotFoundError:
            pass


def open_default_apps():
    if sys.platform == "win32":
        os.startfile("ms-settings:defaultapps")


def set_autostart(enable):
    if sys.platform != "win32":
        return
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
        if enable:
            winreg.SetValueEx(k, APP_NAME, 0, winreg.REG_SZ, _launcher() + " --minimized")
        else:
            try:
                winreg.DeleteValue(k, APP_NAME)
            except FileNotFoundError:
                pass
