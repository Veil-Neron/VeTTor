import time

import libtorrent as lt
from PySide6.QtCore import QAbstractTableModel, QModelIndex, QRectF, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QStyle, QStyledItemDelegate

from ..engine import TF, has_flag
from ..safety import visible_name
from ..util import fmt_eta, fmt_size, fmt_speed
from . import theme
from .safe_text import tip

S = lt.torrent_status
COLUMNS = ["Имя", "Размер", "Прогресс", "Статус", "Сиды", "Пиры", "Загрузка", "Отдача",
           "Осталось", "Рейтинг", "Добавлен"]
C_NAME, C_SIZE, C_PROGRESS, C_STATUS = 0, 1, 2, 3
SORT_ROLE = Qt.UserRole + 1
KEY_ROLE = Qt.UserRole + 2

# Категории фильтра в боковой панели
CATEGORIES = [
    ("all", "Все", "all"),
    ("downloading", "Загружаются", "down"),
    ("seeding", "Раздаются", "up"),
    ("completed", "Завершены", "check"),
    ("active", "Активные", "active"),
    ("paused", "На паузе", "pause"),
    ("error", "С ошибками", "error"),
]


def state_of(st, pending=False):
    """(код, текст) состояния торрента."""
    if st.errc.value():
        return "error", "Ошибка"
    paused = has_flag(st.flags, TF.paused)
    managed = has_flag(st.flags, TF.auto_managed)
    if pending:
        return "meta", "Получение списка файлов" if not st.has_metadata else "Ожидает выбора файлов"
    if paused:
        if st.is_finished:
            return "done", "Завершено"
        return ("queued", "В очереди") if managed else ("paused", "Пауза")
    s = st.state
    if s in (S.checking_files, S.queued_for_checking, S.checking_resume_data):
        return "checking", "Проверка"
    if s == S.downloading_metadata:
        return "meta", "Получение метаданных"
    if s == S.allocating:
        return "checking", "Подготовка"
    if st.is_seeding:
        return "seeding", "Раздача"
    if st.is_finished:
        return "done", "Завершено"
    if st.download_payload_rate <= 0:
        return "stalled", "Ожидание пиров"
    return "downloading", "Загрузка"


def in_category(cat, st, pending):
    code, _ = state_of(st, pending)
    if cat == "all":
        return True
    if cat == "downloading":
        return not st.is_finished and code not in ("paused", "error")
    if cat == "seeding":
        return code == "seeding"
    if cat == "completed":
        return st.is_finished and not pending
    if cat == "active":
        return st.download_payload_rate > 1024 or st.upload_payload_rate > 1024
    if cat == "paused":
        return code in ("paused", "queued", "done") and has_flag(st.flags, TF.paused)
    if cat == "error":
        return code == "error"
    return True


def display_name(st, key):
    return visible_name(st.name) if st.name else f"magnet: {key[:16]}…"


def ratio_of(st):
    return st.all_time_upload / max(st.all_time_download, st.total_wanted, 1)


def eta_of(st):
    left = st.total_wanted - st.total_wanted_done
    if st.is_finished or left <= 0:
        return 0
    rate = st.download_payload_rate
    return left / rate if rate > 0 else None


class TorrentModel(QAbstractTableModel):
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.keys = []
        engine.listChanged.connect(self.sync)
        engine.updated.connect(self.refresh)
        self.sync()

    def sync(self):
        new = list(self.engine.handles.keys())
        if set(new) == set(self.keys):
            return
        self.beginResetModel()
        self.keys = new
        self.endResetModel()

    def refresh(self):
        self.sync()
        if self.keys:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.keys) - 1, len(COLUMNS) - 1))

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.keys)

    def columnCount(self, parent=QModelIndex()):
        return len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return COLUMNS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        key = self.keys[index.row()]
        st = self.engine.status.get(key)
        if st is None:
            return None
        col = index.column()
        if role == KEY_ROLE:
            return key
        pending = self.engine.is_pending(key)
        if role == Qt.DisplayRole:
            return self._display(col, st, key, pending)
        if role == SORT_ROLE:
            return self._sort(col, st, key, pending)
        if role == Qt.TextAlignmentRole and col not in (C_NAME, C_STATUS):
            return int(Qt.AlignRight | Qt.AlignVCenter)
        if role == Qt.ForegroundRole and col == C_STATUS:
            code, _ = self._state(key, st, pending)
            color = {"error": "danger", "downloading": "text", "seeding": "ok"}.get(code, "muted")
            return QColor(theme.current[color])
        if role == Qt.ToolTipRole and col == C_NAME:
            return tip(display_name(st, key))
        if role == Qt.UserRole and col == C_PROGRESS:
            info = self.engine.unpack_info(key)
            if info and info.get("state") == "running":
                return info.get("progress", 0.0), "checking"  # жёлтая полоска — ход распаковки
            return st.progress, self._state(key, st, pending)[0]
        return None

    def _state(self, key, st, pending):
        info = self.engine.unpack_info(key)
        if info:
            state = info.get("state")
            if state == "running":
                return "checking", f"Распаковка {info.get('progress', 0.0) * 100:.0f}%"
            if state == "waiting":
                return "checking", "Подготовка к распаковке"
            if state == "error":
                return "error", "Ошибка распаковки"
        return state_of(st, pending)

    def _display(self, col, st, key, pending):
        if col == C_NAME:
            return display_name(st, key)
        if col == C_SIZE:
            return fmt_size(st.total_wanted) if st.has_metadata else "—"
        if col == C_PROGRESS:
            return f"{st.progress * 100:.1f}%"
        if col == C_STATUS:
            return self._state(key, st, pending)[1]
        if col == 4:
            return f"{st.num_seeds} ({max(st.num_complete, 0)})"
        if col == 5:
            return f"{st.num_peers - st.num_seeds} ({max(st.num_incomplete, 0)})"
        if col == 6:
            return fmt_speed(st.download_payload_rate)
        if col == 7:
            return fmt_speed(st.upload_payload_rate)
        if col == 8:
            if st.is_finished or has_flag(st.flags, TF.paused):
                return ""
            return fmt_eta(eta_of(st))
        if col == 9:
            return f"{ratio_of(st):.2f}"
        if col == 10:
            added = self.engine.added_time(key)
            return time.strftime("%d.%m.%Y %H:%M", time.localtime(added)) if added else ""
        return None

    def _sort(self, col, st, key, pending):
        if col == C_NAME:
            return display_name(st, key).lower()
        if col == C_SIZE:
            return st.total_wanted
        if col == C_PROGRESS:
            return st.progress
        if col == C_STATUS:
            return self._state(key, st, pending)[1]
        if col == 4:
            return st.num_seeds
        if col == 5:
            return st.num_peers - st.num_seeds
        if col == 6:
            return st.download_payload_rate
        if col == 7:
            return st.upload_payload_rate
        if col == 8:
            eta = eta_of(st)
            return 10 ** 12 if eta is None else eta
        if col == 9:
            return ratio_of(st)
        if col == 10:
            return self.engine.added_time(key)
        return 0


class TorrentFilter(QSortFilterProxyModel):
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.category = "all"
        self.text = ""
        self.setSortRole(SORT_ROLE)
        self.setDynamicSortFilter(False)

    def set_category(self, cat):
        self.category = cat
        self.invalidateFilter()

    def set_text(self, text):
        self.text = text.lower().strip()
        self.invalidateFilter()

    def filterAcceptsRow(self, row, parent):
        key = self.sourceModel().keys[row]
        st = self.engine.status.get(key)
        if st is None:
            return False
        if self.text and self.text not in display_name(st, key).lower():
            return False
        return in_category(self.category, st, self.engine.is_pending(key))

    def lessThan(self, left, right):
        a, b = left.data(SORT_ROLE), right.data(SORT_ROLE)
        try:
            return a < b
        except TypeError:
            return str(a) < str(b)


class ProgressDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        if option.state & QStyle.State_Selected:
            painter.fillRect(option.rect, QColor(theme.current["select"]))
        value = index.data(Qt.UserRole)
        if not value:
            return
        progress, code = value
        c = theme.current
        color = {"seeding": c["ok"], "done": c["ok"], "error": c["danger"], "paused": c["muted"],
                 "queued": c["muted"], "checking": c["warn"]}.get(code, theme.ACCENT)
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        r = QRectF(option.rect).adjusted(8, 0, -8, 0)
        bar = QRectF(r.left(), r.center().y() - 3, r.width() - 48, 6)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(c["track"]))
        painter.drawRoundedRect(bar, 3, 3)
        if progress > 0:
            done = QRectF(bar.left(), bar.top(), max(bar.width() * progress, 6), bar.height())
            painter.setBrush(QColor(color))
            painter.drawRoundedRect(done, 3, 3)
        painter.setPen(QColor(c["muted"]))
        text_rect = QRectF(bar.right() + 4, r.top(), 44, r.height())
        painter.drawText(text_rect, Qt.AlignRight | Qt.AlignVCenter, f"{progress * 100:.0f}%")
        painter.restore()
