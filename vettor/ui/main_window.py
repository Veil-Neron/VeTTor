import base64
import json
import os

import libtorrent as lt
from PySide6.QtCore import QEvent, QObject, QRunnable, QSize, Qt, QThreadPool, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QFileDialog, QFrame, QHBoxLayout, QHeaderView,
    QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMenu,
    QMessageBox, QSplitter, QStackedWidget, QStyledItemDelegate, QSystemTrayIcon, QTableView,
    QToolButton, QVBoxLayout, QWidget,
)

from .. import antivirus, diskspace, extract, safety
from ..config import APP_TITLE
from ..engine import file_list, pad_indices, symlink_indices
from ..guard import Guard
from ..unpacker import Unpacker
from ..util import fmt_size, fmt_speed, open_path, reveal_in_explorer
from . import theme
from .add_dialog import AddDialog
from .analysis_view import AnalysisView
from .details import Details
from .icons import app_icon, icon
from .safe_text import ask, warn
from .settings_dialog import SettingsDialog
from .torrent_model import (
    C_NAME, C_PROGRESS, C_STATUS, CATEGORIES, KEY_ROLE, ProgressDelegate, TorrentFilter,
    TorrentModel, display_name, in_category,
)

MAX_TORRENT_FILE_BYTES = 20 * 1024 * 1024
ANALYSIS_ROW = "analysis"


# Сигналы фоновых задач подключаются только к методам окна (не к лямбдам):
# так Qt выполняет обработчик в главном потоке.
class _ScanSignals(QObject):
    done = Signal(str, str, str, bool)  # имя, результат, текст, автоматическая проверка


class _ScanJob(QRunnable):
    def __init__(self, name, path, automatic):
        super().__init__()
        self.name, self.path, self.automatic = name, path, automatic
        self.signals = _ScanSignals()

    def run(self):
        result, text = antivirus.scan(self.path)
        self.signals.done.emit(self.name, result, text, self.automatic)


class _CompactSignals(QObject):
    progress = Signal(int)
    done = Signal(str, bool, int, int, int)  # папка, сжатие, было, стало, код


class _CompactJob(QRunnable):
    def __init__(self, folder, compress):
        super().__init__()
        self.folder, self.compress = folder, compress
        self.signals = _CompactSignals()

    def run(self):
        before = diskspace.size_on_disk(self.folder)
        code = diskspace.compact_folder(self.folder, self.compress, self.signals.progress.emit)
        self.signals.done.emit(self.folder, self.compress, before, diskspace.size_on_disk(self.folder), code)


class SidebarDelegate(QStyledItemDelegate):
    """Рисует счётчик торрентов справа от названия категории."""

    def paint(self, painter, option, index):
        super().paint(painter, option, index)
        count = index.data(Qt.UserRole + 1)
        if count:
            painter.save()
            painter.setPen(QColor(theme.current["muted"]))
            r = option.rect.adjusted(0, 0, -20, 0)
            painter.drawText(r, Qt.AlignRight | Qt.AlignVCenter, str(count))
            painter.restore()

    def sizeHint(self, option, index):
        s = super().sizeHint(option, index)
        return QSize(s.width(), max(s.height(), 34))


class MainWindow(QMainWindow):
    def __init__(self, engine, cfg):
        super().__init__()
        self.engine = engine
        self.cfg = cfg
        self._quitting = False
        self._meta_queue = []
        self._dialog_open = False
        self._tray_hint_shown = False
        self.pool = QThreadPool(self)
        self.setWindowTitle(APP_TITLE)
        self.setWindowIcon(app_icon())
        self.resize(1200, 760)
        self.setAcceptDrops(True)

        root = QWidget()
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        h.addWidget(self._build_sidebar())
        right = QVBoxLayout()
        right.setContentsMargins(0, 0, 0, 0)
        right.setSpacing(0)
        right.addWidget(self._build_toolbar())
        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_downloads())
        self.analysis = AnalysisView()
        self.stack.addWidget(self.analysis)
        right.addWidget(self.stack, 1)
        h.addLayout(right, 1)
        self.setCentralWidget(root)
        self._build_statusbar()
        self._build_tray()
        self._shortcuts()
        self._restore_state()

        engine.updated.connect(self._on_tick)
        engine.listChanged.connect(self._update_empty)
        engine.finished.connect(self._on_finished)
        engine.metadataReady.connect(self._on_metadata)
        engine.message.connect(self._on_message)
        self.guard = Guard(engine)
        self.guard.removed.connect(self._on_guard_removed)
        self.guard.failed.connect(self._on_guard_failed)
        self.unpacker = Unpacker(engine, self.guard)
        self.unpacker.finished.connect(self._on_unpacked)
        self.unpacker.failed.connect(self._on_unpack_failed)
        self.unpacker.notice.connect(self._on_message)
        self._update_empty()
        # Magnet-ссылки, ждавшие выбора файлов при прошлом закрытии
        QTimer.singleShot(500, self._resume_pending)

    # ---------- построение интерфейса ----------
    def _build_sidebar(self):
        side = QFrame()
        side.setObjectName("Sidebar")
        side.setFixedWidth(220)
        lay = QVBoxLayout(side)
        lay.setContentsMargins(0, 0, 0, 12)
        lay.setSpacing(0)
        brand = QLabel(APP_TITLE)
        brand.setObjectName("Brand")
        lay.addWidget(brand)
        self.nav = QListWidget()
        self.nav.setItemDelegate(SidebarDelegate(self.nav))
        self.nav.setIconSize(QSize(18, 18))
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.nav.setTextElideMode(Qt.ElideRight)
        self.nav_items = {}
        for code, name, ic in CATEGORIES:
            it = QListWidgetItem(icon(ic), name)
            it.setData(Qt.UserRole, code)
            self.nav.addItem(it)
            self.nav_items[code] = it
        sep = QListWidgetItem("ИНСТРУМЕНТЫ")
        sep.setFlags(Qt.NoItemFlags)
        f = sep.font()
        f.setPointSize(8)
        f.setBold(True)
        sep.setFont(f)
        sep.setForeground(QColor(theme.current["muted"]))
        self.nav.addItem(sep)
        it = QListWidgetItem(icon("shield"), "Проверка файлов")
        it.setData(Qt.UserRole, ANALYSIS_ROW)
        self.nav.addItem(it)
        self.analysis_item = it
        self.nav.setCurrentRow(0)
        self.nav.currentItemChanged.connect(self._on_nav)
        lay.addWidget(self.nav, 1)
        return side

    def _tool(self, ic, text, slot, tip=None, with_text=False):
        b = QToolButton()
        b.setIcon(icon(ic, theme.current["text"]))
        b.setIconSize(QSize(18, 18))
        b.setText(text)
        b.setToolTip(tip or text)
        b.setToolButtonStyle(Qt.ToolButtonTextBesideIcon if with_text else Qt.ToolButtonIconOnly)
        b.clicked.connect(slot)
        return b

    def _build_toolbar(self):
        bar = QFrame()
        bar.setObjectName("Toolbar")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(4)
        lay.addWidget(self._tool("add", "Файл", self.open_torrent_files, "Добавить .torrent-файл (Ctrl+O)", True))
        lay.addWidget(self._tool("link", "Ссылка", self.ask_link, "Добавить magnet-ссылку (Ctrl+U)", True))
        line = QFrame()
        line.setFrameShape(QFrame.VLine)
        line.setStyleSheet(f"color: {theme.current['border']};")
        lay.addSpacing(6)
        lay.addWidget(line)
        lay.addSpacing(6)
        lay.addWidget(self._tool("play", "Продолжить", lambda: self._each(self.engine.resume)))
        lay.addWidget(self._tool("pause", "Пауза", lambda: self._each(self.engine.pause)))
        lay.addWidget(self._tool("delete", "Удалить", self.remove_selected, "Удалить (Del)"))
        lay.addWidget(self._tool("folder", "Открыть папку", self.open_folder))
        compress = self._tool("compress", "Сжатие", lambda: None, "Сжать папку средствами Windows — освободить место", True)
        menu = QMenu(compress)
        menu.addAction("Сжать папку…", lambda: self.compact_folder(True))
        menu.addAction("Отменить сжатие папки…", lambda: self.compact_folder(False))
        compress.setMenu(menu)
        compress.setPopupMode(QToolButton.InstantPopup)
        lay.addWidget(compress)
        lay.addStretch(1)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Фильтр по имени")
        self.filter.setClearButtonEnabled(True)
        self.filter.addAction(icon("search"), QLineEdit.LeadingPosition)
        self.filter.setFixedWidth(240)
        lay.addWidget(self.filter)
        lay.addWidget(self._tool("settings", "Настройки", lambda: self.open_settings(), "Настройки (Ctrl+,)"))
        return bar

    def _build_downloads(self):
        page = QStackedWidget()
        empty = QLabel("Перетащите сюда .torrent-файл или magnet-ссылку\n"
                       "или нажмите «Файл» / «Ссылка» вверху")
        empty.setObjectName("Empty")
        empty.setAlignment(Qt.AlignCenter)
        page.addWidget(empty)

        self.model = TorrentModel(self.engine)
        self.proxy = TorrentFilter(self.engine)
        self.proxy.setSourceModel(self.model)
        self.filter_text = ""
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(10, Qt.DescendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.setItemDelegateForColumn(C_PROGRESS, ProgressDelegate(self.table))
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.Interactive)
        hh.setStretchLastSection(True)
        hh.setMinimumSectionSize(48)
        hh.setHighlightSections(False)
        hh.setContextMenuPolicy(Qt.CustomContextMenu)
        hh.customContextMenuRequested.connect(self._header_menu)
        for col, w in ((C_NAME, 330), (1, 80), (C_PROGRESS, 130), (C_STATUS, 135), (4, 70), (5, 70),
                       (6, 90), (7, 90), (8, 95), (9, 65), (10, 125)):
            self.table.setColumnWidth(col, w)
        hh.setSectionHidden(10, True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._row_menu)
        self.table.doubleClicked.connect(lambda _: self.open_folder())
        self.table.selectionModel().selectionChanged.connect(self._on_select)

        self.details = Details(self.engine)
        self.splitter = QSplitter(Qt.Vertical)
        wrap = QWidget()
        wl = QVBoxLayout(wrap)
        wl.setContentsMargins(12, 12, 12, 0)
        wl.addWidget(self.table)
        dwrap = QWidget()
        dl = QVBoxLayout(dwrap)
        dl.setContentsMargins(12, 6, 12, 10)
        dl.addWidget(self.details)
        self.splitter.addWidget(wrap)
        self.splitter.addWidget(dwrap)
        self.splitter.setSizes([480, 260])
        page.addWidget(self.splitter)
        self.downloads_page = page
        self.filter.textChanged.connect(self.proxy.set_text)
        return page

    def _build_statusbar(self):
        sb = self.statusBar()
        self.sb_msg = QLabel()
        sb.addWidget(self.sb_msg, 1)
        self.sb_net = QLabel()
        self.sb_dht = QLabel()
        self.sb_speed = QLabel()
        self.alt_btn = QToolButton()
        self.alt_btn.setCheckable(True)
        self.alt_btn.setChecked(self.cfg.alt_enabled)
        self.alt_btn.setIcon(icon("speed", theme.current["text"]))
        self.alt_btn.setToolTip("Альтернативные ограничения скорости")
        self.alt_btn.toggled.connect(self.engine.set_alt_speed)
        for w in (self.sb_net, self.sb_dht, self.sb_speed, self.alt_btn):
            sb.addPermanentWidget(w)
        self._msg_timer = QTimer(self)
        self._msg_timer.setSingleShot(True)
        self._msg_timer.timeout.connect(lambda: self.sb_msg.setText(""))

    def _build_tray(self):
        self.tray = QSystemTrayIcon(app_icon(), self)
        menu = QMenu()
        menu.addAction("Открыть", self.show_window)
        menu.addSeparator()
        menu.addAction(icon("play"), "Продолжить все", self.engine.resume_all)
        menu.addAction(icon("pause"), "Приостановить все", self.engine.pause_all)
        menu.addSeparator()
        menu.addAction("Выход", self.quit)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(
            lambda reason: self.show_window() if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick) else None)
        self.tray.messageClicked.connect(self.show_window)
        self._tray_menu = menu
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()

    def _shortcuts(self):
        for seq, slot in ((QKeySequence.Open, self.open_torrent_files), ("Ctrl+U", self.ask_link),
                          (QKeySequence.Delete, self.remove_selected), (QKeySequence.Find, self.filter.setFocus),
                          ("Ctrl+,", lambda: self.open_settings()), ("Ctrl+Q", self.quit),
                          (QKeySequence.Paste, self._paste)):
            act = QAction(self)
            act.setShortcut(QKeySequence(seq))
            act.triggered.connect(slot)
            self.addAction(act)

    # ---------- состояние окна ----------
    def _restore_state(self):
        try:
            st = json.loads(self.cfg.window_state or "{}")
        except ValueError:
            st = {}
        if st.get("geo"):
            self.restoreGeometry(base64.b64decode(st["geo"]))
        if st.get("header"):
            self.table.horizontalHeader().restoreState(base64.b64decode(st["header"]))
        if st.get("split"):
            self.splitter.restoreState(base64.b64decode(st["split"]))

    def _save_state(self):
        enc = lambda b: base64.b64encode(bytes(b)).decode()  # noqa: E731
        self.cfg.window_state = json.dumps({
            "geo": enc(self.saveGeometry()),
            "header": enc(self.table.horizontalHeader().saveState()),
            "split": enc(self.splitter.saveState()),
        })
        self.cfg.save()

    # ---------- обновление ----------
    def _on_tick(self):
        statuses = self.engine.status
        for code, item in self.nav_items.items():
            item.setData(Qt.UserRole + 1, sum(1 for k, st in statuses.items()
                                              if in_category(code, st, self.engine.is_pending(k))))
        if self.proxy.category != "all":
            self.proxy.invalidateFilter()
        down = sum(st.download_payload_rate for st in statuses.values())
        up = sum(st.upload_payload_rate for st in statuses.values())
        self.sb_speed.setText(f"↓ {fmt_speed(down) or '0 Б/с'}    ↑ {fmt_speed(up) or '0 Б/с'}")
        try:
            nodes = self.engine.ses.status().dht_nodes
            self.sb_dht.setText(f"DHT: {nodes}" if self.cfg.enable_dht else "DHT выкл.")
        except Exception:
            self.sb_dht.setText("")
        bs = self.engine.bind_state
        if bs == "blocked":
            self.sb_net.setText("⚠ Интерфейс VPN недоступен — загрузки остановлены")
            self.sb_net.setStyleSheet(f"color: {theme.current['danger']};")
        elif bs == "ok":
            self.sb_net.setText("Через выбранный интерфейс")
            self.sb_net.setStyleSheet(f"color: {theme.current['ok']};")
        else:
            self.sb_net.setText("")
        scheduled = self.engine.alt_active and not self.cfg.alt_enabled
        self.alt_btn.setToolTip("Альтернативные ограничения включены по расписанию"
                                if scheduled else "Альтернативные ограничения скорости")
        self.tray.setToolTip(f"{APP_TITLE}\n↓ {fmt_speed(down) or '0'}  ↑ {fmt_speed(up) or '0'}")

    def _update_empty(self):
        self.downloads_page.setCurrentIndex(1 if self.engine.handles else 0)

    def _on_nav(self, item, _prev):
        if not item:
            return
        code = item.data(Qt.UserRole)
        if code == ANALYSIS_ROW:
            self.stack.setCurrentIndex(1)
        elif code:
            self.stack.setCurrentIndex(0)
            self.proxy.set_category(code)

    def _on_select(self, *_):
        keys = self.selected_keys()
        self.details.set_key(keys[0] if keys else None)

    def _on_message(self, text):
        self.sb_msg.setText(text)
        self._msg_timer.start(10000)

    def _on_finished(self, key, name):
        if self.cfg.notify_complete and self.tray.isVisible():
            self.tray.showMessage("Загрузка завершена", name, app_icon(), 6000)

    def scan(self, key, automatic=False):
        path = self._content_path(key)
        h = self.engine.handles.get(key)
        if not path or not h:
            return
        name = display_name(self.engine.status[key], key)
        if not automatic:
            self._on_message(f"Проверка антивирусом: {name}…")
        job = _ScanJob(name, path, automatic)
        job.signals.done.connect(self._on_scanned)
        self.pool.start(job)

    def _on_scanned(self, name, result, text, automatic):
        if result == antivirus.THREAT:
            self.show_window()
            warn(self, "Обнаружена угроза", f"«{name}»\n\n{text}.\nНе открывайте файлы из этой раздачи.")
        elif result == antivirus.CLEAN:
            self._on_message(f"«{name}»: {text.lower()}")
            if automatic and self.tray.isVisible() and self.cfg.notify_complete:
                self.tray.showMessage("Проверено антивирусом", f"{name}: угроз не найдено", app_icon(), 4000)
        else:
            self._on_message(f"«{name}»: {text}")

    def _on_guard_removed(self, key, name, reason):
        st = self.engine.status.get(key)
        title = display_name(st, key) if st else ""
        self._on_message(f"Удалён опасный файл «{name}» из «{title}»: {reason}")
        if self.tray.isVisible():
            self.tray.showMessage("Удалён опасный файл", f"{name}\n{reason}", QSystemTrayIcon.Warning, 8000)

    def _on_guard_failed(self, key, name, error):
        self.show_window()
        warn(self, "Не удалось удалить опасный файл",
             f"«{name}» больше не загружается, но удалить его не получилось:\n{error}\n\n"
             "Не открывайте этот файл.")

    def _space_ok(self, ti, prios, folder):
        """Хватит ли места на загрузку. Если нет — торрент добавляется на паузе, а не падает с ошибкой
        посреди загрузки."""
        need = sum(size for (_, size), p in zip(file_list(ti), prios) if p > 0)
        free = diskspace.free_space(folder)
        if free >= need + extract.MARGIN:
            return True
        text = (f"«{ti.name()}»: не хватает места на диске — нужно {fmt_size(need)}, свободно {fmt_size(free)}. "
                "Торрент добавлен на паузе: освободите место (например, кнопкой «Сжатие») и нажмите «Продолжить».")
        self._on_message(text)
        if self.tray.isVisible():
            self.tray.showMessage("Не хватает места", text, QSystemTrayIcon.Warning, 10000)
        return False

    def _on_unpacked(self, key, name, dests):
        where = ", ".join(dests)
        self._on_message(f"«{name}» распакован: {where}")
        if self.tray.isVisible():
            self.tray.showMessage("Распаковано", f"{name}\n{where}", app_icon(), 8000)

    def _on_unpack_failed(self, key, name, error):
        self.show_window()
        warn(self, "Распаковка не удалась", f"«{name}»\n\n{error}")

    def compact_folder(self, compress):
        title = "Сжать папку" if compress else "Отменить сжатие папки"
        folder = QFileDialog.getExistingDirectory(self, title, self.cfg.download_dir)
        if not folder:
            return
        folder = os.path.normpath(folder)
        if compress and not ask(self, title,
                                f"Сжать «{folder}» средствами Windows?\n\nФайлы останутся обычными: программы и игры "
                                "запускаются как раньше. Обычно это освобождает 20–50% места у игр и программ; "
                                "видео, музыка и архивы уже сжаты и почти не уменьшатся. "
                                "Для большой папки это может занять несколько минут.", "Сжать"):
            return
        self._on_message(("Сжатие" if compress else "Отмена сжатия") + f": {folder}…")
        job = _CompactJob(folder, compress)
        job.signals.progress.connect(self._on_compact_progress)
        job.signals.done.connect(self._on_compact_done)
        self.pool.start(job)

    def _on_compact_progress(self, count):
        self._on_message(f"Обработано файлов: {count}…")

    def _on_compact_done(self, folder, compress, before, after, code):
        if code not in (0, 1):
            warn(self, APP_TITLE, f"compact.exe завершился с ошибкой (код {code}) для «{folder}». "
                 "Возможно, нужны права администратора (например, для Program Files).")
            return
        saved = before - after
        text = (f"«{folder}»: было {fmt_size(before)}, стало {fmt_size(after)}"
                + (f" — освобождено {fmt_size(saved)} ({saved / before * 100:.0f}%)." if compress and before and saved > 0 else "."))
        self._on_message(text)
        QMessageBox.information(self, "Сжатие" if compress else "Отмена сжатия", text)

    def _notify_skipped(self, ti):
        pad = pad_indices(ti)
        files = file_list(ti)
        marks, _ = safety.analyze(files, self.cfg, pad, symlink_indices(ti))
        names = [os.path.basename(p) for (p, _), m in zip(files, marks) if m == safety.DANGER]
        if names:
            text = f"«{ti.name()}»: пропущены подозрительные файлы ({len(names)}): " + ", ".join(names[:3])
            self._on_message(text)
            if self.tray.isVisible():
                self.tray.showMessage("Подозрительные файлы пропущены", text, QSystemTrayIcon.Warning, 8000)

    # ---------- выбор торрентов ----------
    def selected_keys(self):
        rows = self.table.selectionModel().selectedRows()
        return [self.proxy.index(r.row(), 0).data(KEY_ROLE) for r in rows]

    def _each(self, fn):
        for k in self.selected_keys():
            fn(k)

    # ---------- добавление ----------
    def handle_args(self, args):
        """Торрент-файлы и magnet-ссылки снаружи (проводник, браузер): загрузка начинается сразу,
        подозрительные файлы отсеиваются автоматически."""
        for a in args:
            if not isinstance(a, str) or len(a) > 65536:
                continue
            if a.lower().startswith("magnet:"):
                self.add_magnet(a)
            elif a.lower().endswith(".torrent") and os.path.isfile(a):
                self.add_torrent_file(a)

    def open_torrent_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Открыть торрент", "", "Торрент-файлы (*.torrent)")
        for p in paths:
            self.add_torrent_file(p)

    def ask_link(self):
        clip = QGuiApplication.clipboard().text().strip()
        default = clip if clip.lower().startswith("magnet:") else ""
        text, ok = QInputDialog.getMultiLineText(
            self, "Добавить magnet-ссылку", "Magnet-ссылки (по одной в строке):", default)
        if ok:
            for line in text.split():
                self.add_link(line.strip())

    def _paste(self):
        text = QGuiApplication.clipboard().text().strip()
        if text.lower().startswith("magnet:") and not self.filter.hasFocus():
            self.add_magnet(text)

    def add_link(self, link):
        if link.lower().startswith("magnet:"):
            self.add_magnet(link)
        elif link:
            self._on_message("Это не magnet-ссылка.")

    def add_torrent_file(self, path):
        try:
            if os.path.getsize(path) > MAX_TORRENT_FILE_BYTES:
                raise ValueError("файл слишком большой для торрента")
            ti = lt.torrent_info(path)
        except Exception as e:
            warn(self, APP_TITLE, f"Не удалось открыть «{os.path.basename(path)}»:\n{e}")
            return
        self.add_torrent_info(ti)

    def add_torrent_info(self, ti):
        if not self.cfg.ask_on_add:
            prios = self._auto_priorities(ti)
            start = not self.cfg.start_paused and self._space_ok(ti, prios, self.cfg.download_dir)
            key = self.engine.add(ti, self.cfg.download_dir, prios, start)
            if key:
                self._notify_skipped(ti)
            return
        self.show_window()
        dlg = AddDialog(self.cfg, ti, self)
        if not dlg.exec():
            return
        path, prios, start, seq = dlg.result_values()
        self.cfg.save()
        self.engine.add(ti, path, prios, start, seq)

    def _auto_priorities(self, ti):
        pad = pad_indices(ti)
        marks, _ = safety.analyze(file_list(ti), self.cfg, pad, symlink_indices(ti))
        return [4 if c and i not in pad else 0 for i, c in enumerate(safety.default_selection(marks, self.cfg))]

    def add_magnet(self, uri):
        try:
            lt.parse_magnet_uri(uri)
        except Exception:
            warn(self, APP_TITLE, "Неверная magnet-ссылка.")
            return
        key = self.engine.add(uri, pending_select=True)
        if key:
            self._on_message("Magnet-ссылка добавлена — получаю список файлов…")

    def _resume_pending(self):
        for key, h in self.engine.handles.items():
            if self.engine.is_pending(key) and h.has_metadata():
                self._on_metadata(key)

    def _on_metadata(self, key):
        if key not in self._meta_queue:
            self._meta_queue.append(key)
        if not self._dialog_open:
            self._next_metadata()

    def _next_metadata(self):
        while self._meta_queue:
            key = self._meta_queue.pop(0)
            h = self.engine.handles.get(key)
            if not h or not self.engine.is_pending(key):
                continue
            ti = h.torrent_file()
            if not ti:
                continue
            if self.cfg.ask_on_add:
                self.show_window()
                self._dialog_open = True
                dlg = AddDialog(self.cfg, ti, self, save_path=h.status().save_path)
                accepted = dlg.exec()
                self._dialog_open = False
                if accepted:
                    path, prios, start, seq = dlg.result_values()
                    self.cfg.save()
                    self.engine.confirm_selection(key, path, prios, start, seq)
                else:
                    self.engine.remove(key, delete_files=True)
            else:
                prios = self._auto_priorities(ti)
                start = not self.cfg.start_paused and self._space_ok(ti, prios, h.status().save_path)
                self.engine.confirm_selection(key, None, prios, start, False)
                self._notify_skipped(ti)

    # ---------- действия ----------
    def remove_selected(self):
        keys = self.selected_keys()
        if not keys:
            return
        delete = False
        if self.cfg.confirm_remove:
            names = [display_name(self.engine.status[k], k) for k in keys if k in self.engine.status]
            box = QMessageBox(self)
            box.setTextFormat(Qt.PlainText)
            box.setWindowTitle("Удаление")
            box.setIcon(QMessageBox.Question)
            box.setText(f"Удалить «{names[0]}»?" if len(names) == 1 else f"Удалить торренты ({len(names)})?")
            cb = QCheckBox("Также удалить скачанные файлы с диска")
            box.setCheckBox(cb)
            yes = box.addButton("Удалить", QMessageBox.AcceptRole)
            box.addButton("Отмена", QMessageBox.RejectRole)
            box.exec()
            if box.clickedButton() is not yes:
                return
            delete = cb.isChecked()
        for k in keys:
            self.engine.remove(k, delete)
        self.details.set_key(None)

    def _content_path(self, key):
        """Файл (одиночный торрент) или корневая папка раздачи — строго внутри папки загрузки."""
        st = self.engine.status.get(key)
        h = self.engine.handles.get(key)
        if not st or not h:
            return None
        save = os.path.realpath(st.save_path)
        ti = h.torrent_file()
        if ti and ti.num_files() > 0:
            first = ti.files().file_path(0).replace("/", os.sep)
            rel = first if ti.num_files() == 1 else first.split(os.sep)[0]
            path = os.path.realpath(os.path.join(save, rel))
            if os.path.commonpath([save, path]) == save and os.path.exists(path):
                return path
        return save

    def _analyze(self, key):
        path = self._content_path(key)
        if not path:
            return
        self.nav.setCurrentItem(self.analysis_item)
        if os.path.isfile(path):
            self.analysis.start(path)
        else:
            self.analysis.pick(path)

    def _unpack_now(self, key):
        if ask(self, "Распаковка", "Архивы будут распакованы рядом, а сами архивы удалены по ходу распаковки — "
               "так нужно меньше свободного места.\n\nРаздача этого торрента прекратится, и он исчезнет из списка "
               "(распакованные файлы останутся). Продолжить?", "Распаковать"):
            self.unpacker.start(key)

    def _open_file(self, path):
        if safety.is_executable(path):
            if not ask(self, "Запуск программы",
                       f"«{os.path.basename(path)}» — это программа или скрипт из торрента.\n\n"
                       "Запускайте только то, чему доверяете. Проверить файл антивирусом можно "
                       "через меню «Проверить антивирусом».", "Всё равно открыть"):
                return
        open_path(path)

    def open_folder(self):
        keys = self.selected_keys()
        if keys:
            path = self._content_path(keys[0])
            if path and os.path.exists(path):
                reveal_in_explorer(path)

    def _row_menu(self, pos):
        keys = self.selected_keys()
        if not keys:
            return
        k = keys[0]
        st = self.engine.status.get(k)
        m = QMenu(self)
        m.addAction(icon("play"), "Продолжить", lambda: self._each(self.engine.resume))
        m.addAction(icon("pause"), "Пауза", lambda: self._each(self.engine.pause))
        m.addAction("Принудительный старт (вне очереди)", lambda: self._each(lambda x: self.engine.resume(x, force=True)))
        m.addSeparator()
        m.addAction(icon("folder"), "Открыть папку", self.open_folder)
        if st and st.is_finished:
            path = self._content_path(k)
            if path and os.path.isfile(path):
                m.addAction(icon("external"), "Открыть файл", lambda: self._open_file(path))
        m.addAction("Переместить…", self._move)
        if self.unpacker.can_unpack(k):
            m.addAction(icon("compress"), "Распаковать и освободить место",
                        lambda: self._unpack_now(k))
        m.addAction(icon("shield"), "Проверить файл подробно…", lambda: self._analyze(k))
        if antivirus.available():
            m.addAction(icon("shield"), "Проверить антивирусом", lambda: self._each(self.scan))
        m.addSeparator()
        seq = m.addAction("Последовательная загрузка")
        seq.setCheckable(True)
        seq.setChecked(bool(st and st.sequential_download))
        seq.toggled.connect(lambda on: self._each(lambda x: self.engine.set_sequential(x, on)))
        m.addAction(icon("speed"), "Ограничить скорость…", self._limits)
        m.addAction(icon("refresh"), "Проверить файлы", lambda: self._each(self.engine.recheck))
        m.addAction("Обновить пиров у трекеров", lambda: self._each(self.engine.reannounce))
        m.addAction(icon("copy"), "Копировать magnet-ссылку",
                    lambda: QGuiApplication.clipboard().setText("\n".join(self.engine.magnet(x) for x in keys)))
        m.addSeparator()
        m.addAction(icon("delete", theme.current["danger"]), "Удалить…", self.remove_selected)
        m.exec(self.table.viewport().mapToGlobal(pos))

    def _header_menu(self, pos):
        hh = self.table.horizontalHeader()
        m = QMenu(self)
        for col in range(1, self.model.columnCount()):
            act = m.addAction(self.model.headerData(col, Qt.Horizontal))
            act.setCheckable(True)
            act.setChecked(not hh.isSectionHidden(col))
            act.toggled.connect(lambda on, c=col: hh.setSectionHidden(c, not on))
        m.exec(hh.mapToGlobal(pos))

    def _move(self):
        keys = self.selected_keys()
        if not keys:
            return
        d = QFileDialog.getExistingDirectory(self, "Переместить в папку", self.engine.status[keys[0]].save_path)
        if d:
            for k in keys:
                self.engine.move(k, os.path.normpath(d))

    def _limits(self):
        keys = self.selected_keys()
        if not keys:
            return
        h = self.engine.handles[keys[0]]
        dl, ok = QInputDialog.getInt(self, "Ограничение скорости", "Загрузка, КБ/с (0 — без ограничений):",
                                     max(h.download_limit(), 0) // 1024, 0, 10 ** 7)
        if not ok:
            return
        ul, ok = QInputDialog.getInt(self, "Ограничение скорости", "Отдача, КБ/с (0 — без ограничений):",
                                     max(h.upload_limit(), 0) // 1024, 0, 10 ** 7)
        if ok:
            for k in keys:
                self.engine.set_limits(k, dl, ul)

    def open_settings(self, page=None):
        old_theme = self.cfg.theme
        dlg = SettingsDialog(self.cfg, self)
        if page:
            dlg.open_page(page)
        if dlg.exec():
            self.engine.apply_settings()
            count = self.engine.load_ip_filter()
            if self.cfg.ip_filter_path:
                self._on_message(f"IP-фильтр: загружено диапазонов — {count}")
            if self.cfg.theme != old_theme:
                theme.apply(QApplication.instance(), self.cfg.theme)
                self._on_message("Тема полностью применится после перезапуска.")

    # ---------- перетаскивание ----------
    def dragEnterEvent(self, e):
        md = e.mimeData()
        if md.hasUrls() or (md.hasText() and md.text().strip().lower().startswith("magnet:")):
            e.acceptProposedAction()

    def dropEvent(self, e):
        md = e.mimeData()
        if md.hasUrls():
            for url in md.urls():
                if url.isLocalFile() and url.toLocalFile().lower().endswith(".torrent"):
                    self.add_torrent_file(url.toLocalFile())
                elif url.scheme() == "magnet":
                    self.add_magnet(url.toString())
        elif md.hasText():
            for line in md.text().split():
                self.add_link(line)

    # ---------- окно и трей ----------
    def show_window(self):
        if self.isMinimized():
            self.showNormal()
        self.show()
        self.raise_()
        self.activateWindow()

    def changeEvent(self, e):
        if e.type() == QEvent.WindowStateChange and self.isMinimized() and \
                self.cfg.minimize_to_tray and self.tray.isVisible():
            QTimer.singleShot(0, self.hide)
        super().changeEvent(e)

    def closeEvent(self, e):
        if not self._quitting and self.cfg.close_to_tray and self.tray.isVisible():
            e.ignore()
            self.hide()
            if not self._tray_hint_shown:
                self._tray_hint_shown = True
                self.tray.showMessage(APP_TITLE, "Программа продолжает работать в области уведомлений.",
                                      app_icon(), 4000)
            return
        e.accept()
        self.quit()

    def quit(self):
        if self._quitting:
            return
        self._quitting = True
        self._save_state()
        self.hide()
        self.tray.hide()
        self.engine.shutdown()
        QApplication.instance().quit()
