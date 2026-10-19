import getpass
import json
import os
import sys

from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import QApplication

from . import config
from .config import APP_NAME, APP_TITLE, ICON_PATH


MAX_IPC_BYTES = 1024 * 1024


def _server_name():
    return f"{APP_NAME}-{getpass.getuser()}"


def _send_to_running(args):
    """Если VeTTor уже запущен — передаём ему ссылки и выходим."""
    sock = QLocalSocket()
    sock.connectToServer(_server_name())
    if not sock.waitForConnected(400):
        return False
    sock.write(json.dumps(args).encode("utf-8"))
    sock.flush()
    sock.waitForBytesWritten(1000)
    sock.disconnectFromServer()
    return True


def main():
    if "--analyze-worker" in sys.argv:
        # Отдельный процесс проверки файла — без окна и без проверки «уже запущено»
        from .analysis.worker import main as worker_main
        i = sys.argv.index("--analyze-worker")
        return worker_main(sys.argv[i + 1:])
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(f"{APP_NAME}.Client")

    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_TITLE)
    app.setQuitOnLastWindowClosed(False)

    if _send_to_running(args or ["--show"]):
        return 0

    from .engine import Engine
    from .ui import theme
    from .ui.icons import app_pixmap
    from .ui.main_window import MainWindow

    migrated = config.migrate_legacy()
    cfg = config.load()
    if migrated:
        from . import winintegration
        winintegration.remove_legacy()
        # Связь с Windows и автозапуск переоформляем на новое имя программы
        if cfg.register_associations:
            winintegration.set_associations(True)
        if cfg.start_with_windows:
            winintegration.set_autostart(True)
    theme.apply(app, cfg.theme)
    os.makedirs(config.DATA_DIR, exist_ok=True)
    if not os.path.exists(ICON_PATH):
        app_pixmap(256).save(ICON_PATH, "ICO")

    engine = Engine(cfg)
    win = MainWindow(engine, cfg)

    server = QLocalServer()
    # Канал доступен только этой учётной записи Windows
    server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
    QLocalServer.removeServer(_server_name())
    server.listen(_server_name())

    def on_connection():
        conn = server.nextPendingConnection()
        buf = bytearray()

        def read():
            buf.extend(bytes(conn.readAll()))
            if len(buf) > MAX_IPC_BYTES:
                conn.abort()
                return
            try:
                incoming = json.loads(buf.decode("utf-8"))
            except ValueError:
                return  # данные пришли не целиком — ждём остальное
            buf.clear()
            if not isinstance(incoming, list):
                return
            args = [a for a in incoming[:100] if isinstance(a, str) and a != "--show"]
            win.show_window()
            win.handle_args(args)
        conn.readyRead.connect(read)
        conn.disconnected.connect(conn.deleteLater)
    server.newConnection.connect(on_connection)

    if "--minimized" not in sys.argv:
        win.show()
    win.handle_args(args)
    code = app.exec()
    server.close()
    return code
