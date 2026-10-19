"""Обёртка над сессией libtorrent: добавление, состояние, сохранение, ограничения."""
import json
import os
import time
import warnings

import libtorrent as lt
from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtNetwork import QAbstractSocket, QNetworkInterface

from .config import APP_NAME, EXTRAS_PATH, RESUME_DIR, VERSION

warnings.filterwarnings("ignore", category=DeprecationWarning, module=__name__)
warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"vettor\..*")

TF = lt.torrent_flags
ALERT_MASK = (
    lt.alert.category_t.error_notification
    | lt.alert.category_t.status_notification
    | lt.alert.category_t.storage_notification
    | lt.alert.category_t.file_progress_notification
)
DHT_ROUTERS = ",".join([
    "dht.libtorrent.org:25401",
    "router.bittorrent.com:6881",
    "router.utorrent.com:6881",
    "dht.transmissionbt.com:6881",
])


def has_flag(flags, flag):
    return bool(int(flags) & int(flag))


def ih_key(info_hashes):
    return str(info_hashes.get_best())


def handle_key(h):
    return ih_key(h.info_hashes())


def file_list(ti):
    fs = ti.files()
    return [(fs.file_path(i), fs.file_size(i)) for i in range(fs.num_files())]


def symlink_indices(ti):
    fs = ti.files()
    return {i for i in range(fs.num_files()) if fs.file_flags(i) & lt.file_storage.flag_symlink}


def downloaded_paths(h):
    """Полные пути выбранных (не пропущенных) файлов торрента."""
    ti = h.torrent_file()
    if not ti:
        return []
    save = h.status().save_path
    prios = list(h.get_file_priorities())
    pads = pad_indices(ti)
    return [os.path.join(save, path) for i, (path, _) in enumerate(file_list(ti))
            if i not in pads and prios[i] > 0]


ZONE_ID = "[ZoneTransfer]\r\nZoneId=3\r\n"


def mark_of_the_web(paths):
    """Помечает файлы как загруженные из интернета (как это делают браузеры).
    Тогда Windows SmartScreen и Office проверяют их перед запуском."""
    for path in paths:
        try:
            if os.path.isfile(path):
                with open(path + ":Zone.Identifier", "w", encoding="ascii", newline="") as f:
                    f.write(ZONE_ID)
        except OSError:
            pass  # не NTFS (флешка FAT32) — метку поставить нельзя


def pad_indices(ti):
    """Служебные файлы-выравниватели гибридных торрентов: их не показываем и не качаем."""
    fs = ti.files()
    return {i for i in range(fs.num_files()) if fs.file_flags(i) & lt.file_storage.flag_pad_file}


def _in_window(start, end):
    def minutes(s):
        h, m = s.split(":")
        return int(h) * 60 + int(m)
    try:
        a, b = minutes(start), minutes(end)
    except ValueError:
        return False
    t = time.localtime()
    now = t.tm_hour * 60 + t.tm_min
    return a <= now < b if a <= b else (now >= a or now < b)


class Engine(QObject):
    listChanged = Signal()
    updated = Signal()
    finished = Signal(str, str)  # ключ, имя
    completed = Signal(str)  # ключ: загрузка завершена (в т.ч. повторно после смены файлов)
    fileCompleted = Signal(str, int)  # ключ, индекс докачанного файла
    torrentPaused = Signal(str)
    fileError = Signal(str, str)  # ключ, путь файла
    metadataReady = Signal(str)  # ключ торрента, ждущего выбора файлов
    message = Signal(str)

    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg
        os.makedirs(RESUME_DIR, exist_ok=True)
        self.handles = {}
        self.status = {}
        self.extras = self._load_extras()
        self.alt_active = self._want_alt()
        self.bind_state = ""  # "" — любой интерфейс, "ok", "blocked"
        self._bind_ip = None
        self._ticks = 0
        self._readd = {}  # ключ -> (старый handle, параметры для повторного добавления)
        self.ses = lt.session(self._settings_pack())
        self._apply_bind_pause()
        self.load_ip_filter()
        self._load_resume()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(1000)

    # ---------- настройки ----------
    def _resolve_bind(self):
        name = self.cfg.bind_interface
        if not name:
            return None, ""
        iface = QNetworkInterface.interfaceFromName(name)
        if iface.isValid() and bool(iface.flags() & QNetworkInterface.InterfaceFlag.IsUp):
            for entry in iface.addressEntries():
                ip = entry.ip()
                if ip.protocol() == QAbstractSocket.NetworkLayerProtocol.IPv4Protocol:
                    return ip.toString(), "ok"
        # Интерфейс (например, VPN) пропал — не выпускаем трафик мимо него.
        return "127.0.0.1", "blocked"

    def _want_alt(self):
        c = self.cfg
        return c.alt_enabled or (c.schedule_enabled and _in_window(c.schedule_from, c.schedule_to))

    def _settings_pack(self):
        c = self.cfg
        ip, self.bind_state = self._resolve_bind()
        self._bind_ip = ip
        port = int(c.listen_port)
        listen = f"{ip}:{port}" if ip else f"0.0.0.0:{port},[::]:{port}"
        dl, ul = (c.alt_dl_limit_kib, c.alt_ul_limit_kib) if self.alt_active else (c.dl_limit_kib, c.ul_limit_kib)
        enc = [lt.enc_policy.enabled, lt.enc_policy.forced, lt.enc_policy.disabled][int(c.encryption)]
        if c.proxy_type == "socks5" and c.proxy_host:
            ptype = lt.proxy_type_t.socks5_pw if c.proxy_user else lt.proxy_type_t.socks5
        elif c.proxy_type == "http" and c.proxy_host:
            ptype = lt.proxy_type_t.http_pw if c.proxy_user else lt.proxy_type_t.http
        else:
            ptype = lt.proxy_type_t.none
        return {
            "user_agent": f"{APP_NAME}/{VERSION} libtorrent/{lt.__version__}",
            "listen_interfaces": listen,
            "outgoing_interfaces": ip or "",
            "enable_dht": c.enable_dht,
            "enable_lsd": c.enable_lsd,
            "enable_upnp": c.enable_upnp and not ip,
            "enable_natpmp": c.enable_natpmp and not ip,
            "dht_bootstrap_nodes": DHT_ROUTERS,
            "download_rate_limit": int(dl) * 1024,
            "upload_rate_limit": int(ul) * 1024,
            "out_enc_policy": int(enc),
            "in_enc_policy": int(enc),
            "allowed_enc_level": int(lt.enc_level.both),
            "prefer_rc4": int(c.encryption) == 1,
            "anonymous_mode": c.anonymous_mode,
            "connections_limit": int(c.max_connections),
            "active_downloads": int(c.max_active_downloads),
            "active_seeds": int(c.max_active_seeds),
            "active_limit": int(c.max_active_downloads) + int(c.max_active_seeds) + 4,
            "alert_mask": int(ALERT_MASK),
            "proxy_type": int(ptype),
            "proxy_hostname": c.proxy_host,
            "proxy_port": int(c.proxy_port or 0),
            "proxy_username": c.proxy_user,
            "proxy_password": c.proxy_password,
            "proxy_peer_connections": c.proxy_peers,
            "proxy_tracker_connections": True,
            "proxy_hostnames": True,
        }

    def apply_settings(self):
        self.alt_active = self._want_alt()
        self.ses.apply_settings(self._settings_pack())
        self._apply_bind_pause()
        self.updated.emit()

    def _apply_bind_pause(self):
        if self.bind_state == "blocked":
            self.ses.pause()
        elif self.ses.is_paused():
            self.ses.resume()

    def set_alt_speed(self, on):
        self.cfg.alt_enabled = on
        self.cfg.save()
        self.apply_settings()

    def load_ip_filter(self):
        path = self.cfg.ip_filter_path
        f = lt.ip_filter()
        count = 0
        if path and os.path.isfile(path):
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        rng = _parse_filter_line(line)
                        if rng:
                            f.add_rule(rng[0], rng[1], 1)
                            count += 1
            except OSError as e:
                self.message.emit(f"Не удалось прочитать IP-фильтр: {e}")
        self.ses.set_ip_filter(f)
        return count

    # ---------- добавление и управление ----------
    def add(self, source, save_path=None, priorities=None, start=True,
            sequential=False, pending_select=False):
        """source — magnet-ссылка (str) или lt.torrent_info. Возвращает ключ или None."""
        if isinstance(source, lt.torrent_info):
            atp = lt.add_torrent_params()
            atp.ti = source
            key = ih_key(source.info_hashes())
        else:
            atp = lt.parse_magnet_uri(source)
            key = ih_key(atp.info_hashes)
        if key in self.handles:
            h = self.handles[key]
            for url in list(atp.trackers):
                h.add_tracker({"url": url})
            self.message.emit("Этот торрент уже есть в списке — новые трекеры добавлены к нему.")
            return None

        atp.save_path = save_path or self.cfg.download_dir
        if priorities is not None:
            atp.file_priorities = priorities
        flags = int(TF.update_subscribe) | int(TF.apply_ip_filter)
        flags |= (int(TF.auto_managed) | int(TF.paused)) if start else int(TF.paused)
        if sequential:
            flags |= int(TF.sequential_download)
        if pending_select:
            flags |= int(TF.default_dont_download)
        if not self.cfg.enable_pex:
            flags |= int(TF.disable_pex)
        atp.flags = flags

        h = self.ses.add_torrent(atp)
        key = handle_key(h)
        self.handles[key] = h
        self.extras[key] = {"added": time.time(), "pending_select": pending_select}
        self._save_extras()
        self.status[key] = h.status()
        self._request_save(h)
        self.listChanged.emit()
        return key

    def confirm_selection(self, key, save_path, priorities, start, sequential):
        """Завершает добавление magnet-ссылки после выбора файлов."""
        h = self.handles.get(key)
        if not h:
            return
        if save_path and os.path.normcase(save_path) != os.path.normcase(h.status().save_path):
            h.move_storage(save_path)
        h.prioritize_files(priorities)
        h.set_sequential_download(sequential)
        self.extras.setdefault(key, {})["pending_select"] = False
        self._save_extras()
        if not start:
            self.pause(key)
        self._request_save(h)

    def remove(self, key, delete_files=False):
        h = self.handles.pop(key, None)
        if not h:
            return
        self.ses.remove_torrent(h, lt.options_t.delete_files if delete_files else 0)
        self.status.pop(key, None)
        self.extras.pop(key, None)
        self._save_extras()
        try:
            os.remove(os.path.join(RESUME_DIR, key + ".fastresume"))
        except OSError:
            pass
        self.listChanged.emit()

    def pause(self, key):
        h = self.handles.get(key)
        if h:
            h.unset_flags(TF.auto_managed)
            h.pause()
            self._request_save(h)

    def resume(self, key, force=False):
        h = self.handles.get(key)
        if not h:
            return
        if (self.unpack_info(key) or {}).get("state") in ("waiting", "running", "error"):
            return  # архив распаковывается (или уже частично освобождён) — раздавать нечего
        ex = self.extras.setdefault(key, {})
        if ex.get("limit_reached"):
            ex["ignore_limits"] = True
            self._save_extras()
        if h.status().errc.value():
            h.clear_error()
        if force:
            h.unset_flags(TF.auto_managed)
        else:
            h.set_flags(TF.auto_managed)
        h.resume()
        self._request_save(h)

    def pause_all(self):
        for k in self.handles:
            self.pause(k)

    def resume_all(self):
        for k in self.handles:
            self.resume(k)

    def recheck(self, key):
        h = self.handles.get(key)
        if h:
            h.force_recheck()

    def reannounce(self, key):
        h = self.handles.get(key)
        if h:
            h.force_reannounce()
            if self.cfg.enable_dht:
                h.force_dht_announce()

    def set_sequential(self, key, on):
        h = self.handles.get(key)
        if h:
            h.set_sequential_download(on)

    def move(self, key, path):
        h = self.handles.get(key)
        if h:
            h.move_storage(path)

    def set_limits(self, key, dl_kib, ul_kib):
        h = self.handles.get(key)
        if h:
            h.set_download_limit(int(dl_kib) * 1024 if dl_kib else -1)
            h.set_upload_limit(int(ul_kib) * 1024 if ul_kib else -1)

    def magnet(self, key):
        h = self.handles.get(key)
        return lt.make_magnet_uri(h) if h else ""

    def file_path(self, key, index):
        """Полный путь файла торрента — только если он внутри папки загрузки."""
        h = self.handles.get(key)
        ti = h.torrent_file() if h else None
        if not ti or not 0 <= index < ti.num_files():
            return None
        save = os.path.realpath(h.status().save_path)
        path = os.path.realpath(os.path.join(save, ti.files().file_path(index)))
        return path if os.path.commonpath([save, path]) == save else None

    def drop_files(self, key, indices, start):
        """Убирает из торрента уже удалённые с диска файлы без перепроверки остальных.

        Перепроверка (force_recheck) ломает гибридные v1+v2 торренты, поэтому торрент
        переподключается к сессии со списком имеющихся кусков, из которого вычеркнуты куски
        удалённых файлов. Куски на стыке с соседними файлами (бывают только у v1) потом
        докачиваются заново — данные соседних файлов при этом не меняются."""
        h = self.handles.get(key)
        ti = h.torrent_file() if h else None
        if not ti:
            return
        st = h.status()
        have = list(h.status(lt.status_flags_t.query_pieces).pieces)
        fs = ti.files()
        for i in indices:
            if fs.file_size(i) <= 0:
                continue
            first = ti.map_file(i, 0, 0).piece
            last = ti.map_file(i, fs.file_size(i) - 1, 0).piece
            for p in range(first, last + 1):
                have[p] = False
        atp = lt.add_torrent_params()
        atp.ti = ti
        atp.save_path = st.save_path
        atp.file_priorities = list(h.get_file_priorities())
        atp.have_pieces = have
        atp.trackers = [t["url"] for t in h.trackers()]
        atp.url_seeds = list(h.url_seeds())
        atp.total_uploaded = st.all_time_upload
        atp.total_downloaded = st.all_time_download
        atp.added_time = st.added_time
        atp.download_limit = h.download_limit()
        atp.upload_limit = h.upload_limit()
        flags = int(TF.update_subscribe) | int(TF.apply_ip_filter)
        flags |= (int(TF.auto_managed) | int(TF.paused)) if start else int(TF.paused)
        if st.sequential_download:
            flags |= int(TF.sequential_download)
        atp.flags = flags
        self._readd[key] = (h, atp)
        self.ses.remove_torrent(h)  # файлы остаются на месте

    def _finish_readd(self):
        for key, (old, atp) in list(self._readd.items()):
            if old.is_valid():
                continue  # libtorrent ещё не закончил удаление
            del self._readd[key]
            h = self.ses.add_torrent(atp)
            self.handles[key] = h
            self.status[key] = h.status()
            self._request_save(h)

    def file_index(self, key, path):
        h = self.handles.get(key)
        ti = h.torrent_file() if h else None
        if not ti or not path:
            return None
        target = os.path.normcase(os.path.realpath(path))
        for i in range(ti.num_files()):
            p = self.file_path(key, i)
            if p and os.path.normcase(p) == target:
                return i
        return None

    def unpack_info(self, key):
        """Состояние распаковки: {"state": waiting|running|error, "progress", "error"} или None."""
        return self.extras.get(key, {}).get("unpack")

    def set_unpack(self, key, info):
        ex = self.extras.setdefault(key, {})
        if info is None:
            ex.pop("unpack", None)
        else:
            ex["unpack"] = info
        self._save_extras()

    def note_removed(self, key, name, reason):
        self.extras.setdefault(key, {}).setdefault("removed", []).append({"name": name, "reason": reason})
        self._save_extras()

    def removed_files(self, key):
        return self.extras.get(key, {}).get("removed", [])

    def is_pending(self, key):
        return bool(self.extras.get(key, {}).get("pending_select"))

    def added_time(self, key):
        st = self.status.get(key)
        return self.extras.get(key, {}).get("added") or (st.added_time if st else 0)

    # ---------- цикл ----------
    def _tick(self):
        self._ticks += 1
        self._process_alerts()
        if self._readd:
            self._finish_readd()
        if self._ticks % 10 == 0:
            ip, _ = self._resolve_bind()
            if ip != self._bind_ip:
                self.apply_settings()
                if self.bind_state == "blocked":
                    self.message.emit("Выбранный сетевой интерфейс недоступен — загрузки остановлены.")
                elif self.bind_state == "ok":
                    self.message.emit("Сетевой интерфейс снова доступен — загрузки продолжены.")
        if self._ticks % 30 == 0 and self._want_alt() != self.alt_active:
            self.apply_settings()
        for k, h in list(self.handles.items()):
            if h.is_valid():
                self.status[k] = h.status()
        self._enforce_seed_limits()
        if self._ticks % 300 == 0:
            for h in self.handles.values():
                if h.need_save_resume_data():
                    self._request_save(h)
        self.updated.emit()

    def _enforce_seed_limits(self):
        ratio_limit, time_limit = float(self.cfg.ratio_limit), int(self.cfg.seed_time_limit_min)
        if ratio_limit <= 0 and time_limit <= 0:
            return
        for k, st in self.status.items():
            if not st.is_seeding or has_flag(st.flags, TF.paused):
                continue
            ex = self.extras.setdefault(k, {})
            if ex.get("ignore_limits"):
                continue
            ratio = st.all_time_upload / max(st.all_time_download, st.total_wanted, 1)
            minutes = st.seeding_duration.total_seconds() / 60
            if (ratio_limit > 0 and ratio >= ratio_limit) or (time_limit > 0 and minutes >= time_limit):
                ex["limit_reached"] = True
                self._save_extras()
                self.pause(k)
                self.message.emit(f"«{st.name}»: раздача остановлена — достигнут лимит.")

    def _process_alerts(self):
        for a in self.ses.pop_alerts():
            try:
                self._handle_alert(a)
            except RuntimeError:
                pass  # событие от торрента, который уже убран из сессии

    def _handle_alert(self, a):
        if isinstance(a, lt.save_resume_data_alert):
            self._write_resume(a)
        elif isinstance(a, lt.metadata_received_alert):
            key = handle_key(a.handle)
            self._request_save(a.handle)
            if self.is_pending(key):
                self.metadataReady.emit(key)
        elif isinstance(a, lt.torrent_finished_alert):
            self._on_finished(a.handle)
        elif isinstance(a, lt.file_completed_alert):
            self.fileCompleted.emit(handle_key(a.handle), int(a.index))
        elif isinstance(a, lt.torrent_paused_alert):
            self.torrentPaused.emit(handle_key(a.handle))
        elif isinstance(a, lt.file_error_alert):
            self.fileError.emit(handle_key(a.handle), a.filename())
            self.message.emit(f"{a.torrent_name}: {a.message()}")
        elif isinstance(a, lt.torrent_error_alert):
            self.message.emit(f"{a.torrent_name}: {a.message()}")
        elif isinstance(a, lt.listen_failed_alert):
            if self.bind_state != "blocked":
                self.message.emit(f"Не удалось открыть порт: {a.message()}")

    def _on_finished(self, h):
        key = handle_key(h)
        self._request_save(h)
        st = h.status()
        ex = self.extras.setdefault(key, {})
        if st.total_wanted > 0 and not ex.get("pending_select"):
            if self.cfg.mark_of_the_web:
                mark_of_the_web(downloaded_paths(h))
            self.completed.emit(key)
        if st.total_wanted > 0 and not ex.get("pending_select") and not ex.get("notified"):
            ex["notified"] = True
            self._save_extras()
            self.finished.emit(key, st.name)

    # ---------- сохранение ----------
    def _request_save(self, h):
        if h.is_valid() and h.has_metadata():
            h.save_resume_data(lt.save_resume_flags_t.save_info_dict)
        elif h.is_valid():
            h.save_resume_data()

    def _write_resume(self, alert):
        try:
            key = handle_key(alert.handle)
        except RuntimeError:
            return
        # Ответ от старого экземпляра торрента (до drop_files) содержит удалённые куски — не пишем
        if key not in self.handles or alert.handle != self.handles[key] or key in self._readd:
            return
        path = os.path.join(RESUME_DIR, key + ".fastresume")
        tmp = path + ".tmp"
        try:
            with open(tmp, "wb") as f:
                f.write(lt.write_resume_data_buf(alert.params))
            os.replace(tmp, path)
        except OSError as e:
            self.message.emit(f"Не удалось сохранить состояние торрента: {e}")

    def _load_resume(self):
        for name in sorted(os.listdir(RESUME_DIR)):
            if not name.endswith(".fastresume"):
                continue
            path = os.path.join(RESUME_DIR, name)
            try:
                with open(path, "rb") as f:
                    atp = lt.read_resume_data(f.read())
                h = self.ses.add_torrent(atp)
                key = handle_key(h)
                self.handles[key] = h
                self.status[key] = h.status()
            except Exception as e:  # повреждённый файл не должен ломать запуск
                self.message.emit(f"Пропущен повреждённый файл {name}: {e}")

    def _load_extras(self):
        try:
            with open(EXTRAS_PATH, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _save_extras(self):
        tmp = EXTRAS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.extras, f)
        os.replace(tmp, EXTRAS_PATH)

    def shutdown(self):
        self.timer.stop()
        deadline = time.time() + 5
        while self._readd and time.time() < deadline:
            self.ses.pop_alerts()
            self._finish_readd()
            time.sleep(0.05)
        self.ses.pause()
        pending = 0
        for h in self.handles.values():
            if h.is_valid():
                self._request_save(h)
                pending += 1
        deadline = time.time() + 8
        while pending > 0 and time.time() < deadline:
            if not self.ses.wait_for_alert(500):
                continue
            for a in self.ses.pop_alerts():
                if isinstance(a, lt.save_resume_data_alert):
                    self._write_resume(a)
                    pending -= 1
                elif isinstance(a, lt.save_resume_data_failed_alert):
                    pending -= 1
        self._save_extras()


def _parse_filter_line(line):
    """Поддерживает форматы eMule (.dat) и PeerGuardian (.p2p)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    try:
        if "," in line and " - " in line:  # 1.2.3.4 - 1.2.3.255 , 000 , описание
            rng, level = line.split(",")[:2]
            if int(level.strip()) > 127:
                return None
            a, b = rng.split("-")
        else:  # описание:1.2.3.4-1.2.3.255
            a, b = line.rsplit(":", 1)[1].split("-")
        return _norm_ip(a), _norm_ip(b)
    except (ValueError, IndexError):
        return None


def _norm_ip(ip):
    return ".".join(str(int(p)) for p in ip.strip().split("."))
