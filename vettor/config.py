"""Настройки приложения: хранятся в %APPDATA%\\VeTTor\\settings.json."""
import json
import os
import random
from dataclasses import asdict, dataclass, field, fields

from . import secure

APP_NAME = "VeTTor"
APP_TITLE = "VeTTor"
VERSION = "1.3.0"
CONFIG_VERSION = 2

DATA_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), APP_NAME)
RESUME_DIR = os.path.join(DATA_DIR, "resume")
CONFIG_PATH = os.path.join(DATA_DIR, "settings.json")
EXTRAS_PATH = os.path.join(DATA_DIR, "torrents.json")
ICON_PATH = os.path.join(DATA_DIR, "vettor.ico")
# До версии 1.3 программа называлась «Поток» и хранила данные здесь
LEGACY_DATA_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "Potok")


def migrate_legacy():
    """Переносит настройки, торренты и историю проверок из папки «Потока». Старая папка
    остаётся нетронутой как резервная копия. Возвращает True, если перенос был."""
    if os.path.exists(DATA_DIR) or not os.path.isdir(LEGACY_DATA_DIR):
        return False
    import shutil
    shutil.copytree(LEGACY_DATA_DIR, DATA_DIR,
                    ignore=shutil.ignore_patterns("potok.ico", "ui_*.png", "analysis_work", "*.tmp"))
    return True


def _default_download_dir():
    return os.path.join(os.path.expanduser("~"), "Downloads")


@dataclass
class Config:
    # Основные
    download_dir: str = field(default_factory=_default_download_dir)
    ask_on_add: bool = False  # по умолчанию загрузка начинается сразу, без окна выбора файлов
    start_paused: bool = False
    theme: str = "system"  # system | dark | light
    minimize_to_tray: bool = True
    close_to_tray: bool = True
    notify_complete: bool = True
    start_with_windows: bool = False
    register_associations: bool = False
    confirm_remove: bool = True

    # Скорость (КиБ/с, 0 — без ограничений)
    dl_limit_kib: int = 0
    ul_limit_kib: int = 0
    alt_dl_limit_kib: int = 2048
    alt_ul_limit_kib: int = 256
    alt_enabled: bool = False
    schedule_enabled: bool = False
    schedule_from: str = "09:00"
    schedule_to: str = "18:00"

    # Подключение
    listen_port: int = 0
    enable_upnp: bool = True
    enable_natpmp: bool = True
    max_connections: int = 300
    max_active_downloads: int = 4
    max_active_seeds: int = 6

    # Приватность и безопасность
    encryption: int = 0  # 0 — предпочитать, 1 — требовать, 2 — отключить
    anonymous_mode: bool = False
    enable_dht: bool = True
    enable_lsd: bool = True
    enable_pex: bool = True
    bind_interface: str = ""  # системное имя сетевого интерфейса (например, VPN)
    proxy_type: str = "none"  # none | socks5 | http
    proxy_host: str = ""
    proxy_port: int = 1080
    proxy_user: str = ""
    proxy_password: str = ""
    proxy_peers: bool = True
    ip_filter_path: str = ""

    # Фильтр лишних файлов
    skip_junk: bool = True
    junk_extensions: list = field(default_factory=lambda: [
        ".url", ".website", ".webloc", ".lnk", ".html", ".htm", ".mht", ".torrent",
    ])
    junk_keywords: list = field(default_factory=lambda: [
        "реклама", "promo", "advert", "скачано с", "downloaded from", "visit ", "www.",
        "sample", "rarbg", "torrent downloaded",
    ])
    warn_dangerous: bool = True
    mark_of_the_web: bool = True  # помечать скачанное как «из интернета» для SmartScreen
    guard_enabled: bool = True  # проверять каждый докачанный файл и удалять заражённые

    # Экономия места
    extract_mode: str = "always"  # always | needed | never — распаковывать архивы после загрузки
    compress_extracted: bool = False  # сжимать распакованное средствами Windows (NTFS LZX)

    # Раздача
    ratio_limit: float = 0.0
    seed_time_limit_min: int = 0

    # Внутреннее
    config_version: int = 1  # файлы без этого поля — первая версия
    window_state: str = ""
    recent_dirs: list = field(default_factory=list)

    def save(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = CONFIG_PATH + ".tmp"
        data = asdict(self)
        data["proxy_password"] = secure.protect(self.proxy_password)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, CONFIG_PATH)

    def remember_dir(self, path):
        dirs = [d for d in self.recent_dirs if d != path]
        self.recent_dirs = [path] + dirs[:7]


def load():
    cfg = Config()
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
        for f in fields(Config):
            if f.name not in data:
                continue
            v, default = data[f.name], getattr(cfg, f.name)
            # испорченный или подменённый файл не должен ломать программу
            if isinstance(default, bool):
                ok = isinstance(v, bool)
            elif isinstance(default, (int, float)):
                ok = isinstance(v, (int, float)) and not isinstance(v, bool)
            else:
                ok = isinstance(v, type(default))
            if ok:
                setattr(cfg, f.name, v)
    except (OSError, ValueError):
        pass
    cfg.proxy_password = secure.unprotect(cfg.proxy_password)
    if cfg.config_version < 2:
        # Версия 2: загрузка сразу, без окна выбора файлов (поиск убран)
        cfg.ask_on_add = False
        cfg.config_version = CONFIG_VERSION
        cfg.save()
    if not cfg.listen_port:
        # Случайный порт вместо стандартного 6881 — его часто режут провайдеры.
        cfg.listen_port = random.randint(20000, 60000)
        cfg.save()
    return cfg
