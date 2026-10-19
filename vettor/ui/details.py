import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QFormLayout, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QPushButton,
    QScrollArea, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

from ..engine import file_list, pad_indices
from ..util import fmt_size, fmt_speed
from .file_tree import FileTree
from .torrent_model import ratio_of, state_of


def _table(headers):
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().hide()
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setShowGrid(False)
    t.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
    for i in range(1, len(headers)):
        t.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeToContents)
    return t


def _fill(table, rows, right_cols=()):
    table.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, value in enumerate(row):
            item = table.item(r, c)
            if item is None:
                item = QTableWidgetItem()
                if c in right_cols:
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                table.setItem(r, c, item)
            if item.text() != str(value):
                item.setText(str(value))


class Details(QTabWidget):
    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.key = None
        self._files_key = None

        # Общее
        general = QWidget()
        form = QFormLayout(general)
        form.setLabelAlignment(Qt.AlignRight)
        form.setHorizontalSpacing(16)
        self.fields = {}
        for name in ["Состояние", "Папка", "Размер", "Загружено", "Отдано", "Рейтинг", "Скорость",
                     "Пиры", "Доступность", "Добавлен", "Создан", "Хэш", "Комментарий", "Удалено защитой"]:
            lbl = QLabel()
            lbl.setTextFormat(Qt.PlainText)
            lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            lbl.setWordWrap(True)
            form.addRow(name + ":", lbl)
            self.fields[name] = lbl
        scroll = QScrollArea()
        scroll.setWidget(general)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        self.addTab(scroll, "Общее")

        # Файлы
        self.files = FileTree(show_progress=True)
        self.files.selectionChangedByUser.connect(self._files_checked)
        self.files.priorityRequested.connect(self._set_priority)
        self.addTab(self.files, "Файлы")

        # Пиры
        self.peers = _table(["Адрес", "Клиент", "Прогресс", "Загрузка", "Отдача", "Шифрование"])
        self.addTab(self.peers, "Пиры")

        # Трекеры
        trackers = QWidget()
        tl = QVBoxLayout(trackers)
        tl.setContentsMargins(0, 0, 0, 0)
        self.trackers = _table(["Адрес", "Уровень", "Статус"])
        tl.addWidget(self.trackers)
        row = QHBoxLayout()
        row.setContentsMargins(8, 0, 8, 8)
        add = QPushButton("Добавить трекер…")
        add.clicked.connect(self._add_tracker)
        row.addWidget(add)
        row.addStretch(1)
        tl.addLayout(row)
        self.addTab(trackers, "Трекеры")

        self.currentChanged.connect(lambda _: self.refresh())
        engine.updated.connect(self.refresh)

    def set_key(self, key):
        self.key = key
        self._files_key = None
        self.refresh()

    def refresh(self):
        if not self.isVisible():
            return
        h = self.engine.handles.get(self.key) if self.key else None
        st = self.engine.status.get(self.key) if self.key else None
        if not h or st is None:
            for lbl in self.fields.values():
                lbl.setText("")
            self.files.clear()
            self._files_key = None
            self.peers.setRowCount(0)
            self.trackers.setRowCount(0)
            return
        tab = self.currentIndex()
        if tab == 0:
            self._general(h, st)
        elif tab == 1:
            self._files(h, st)
        elif tab == 2:
            self._peers(h)
        elif tab == 3:
            self._trackers(h)

    def _general(self, h, st):
        f = self.fields
        f["Состояние"].setText(state_of(st, self.engine.is_pending(self.key))[1]
                               + (f" — {st.errc.message()}" if st.errc.value() else ""))
        f["Папка"].setText(st.save_path)
        f["Размер"].setText(f"{fmt_size(st.total_wanted)} (выбрано) из {fmt_size(st.total)}"
                            if st.has_metadata else "—")
        f["Загружено"].setText(f"{fmt_size(st.total_wanted_done)} · всего {fmt_size(st.all_time_download)}")
        f["Отдано"].setText(fmt_size(st.all_time_upload))
        f["Рейтинг"].setText(f"{ratio_of(st):.3f}")
        f["Скорость"].setText(f"↓ {fmt_speed(st.download_payload_rate) or '0'}   ↑ {fmt_speed(st.upload_payload_rate) or '0'}")
        f["Пиры"].setText(f"сиды {st.num_seeds} из {max(st.num_complete, 0)}, "
                          f"личи {st.num_peers - st.num_seeds} из {max(st.num_incomplete, 0)}")
        f["Доступность"].setText(f"{st.distributed_copies:.2f}" if st.distributed_copies >= 0 else "—")
        added = self.engine.added_time(self.key)
        f["Добавлен"].setText(time.strftime("%d.%m.%Y %H:%M", time.localtime(added)) if added else "")
        ti = h.torrent_file()
        if ti:
            created = ti.creation_date()
            f["Создан"].setText((time.strftime("%d.%m.%Y", time.localtime(created)) if created else "")
                                + (f" · {ti.creator()}" if ti.creator() else ""))
            f["Комментарий"].setText(ti.comment())
        f["Хэш"].setText(self.key)
        removed = self.engine.removed_files(self.key)
        f["Удалено защитой"].setText(
            "\n".join(f"{r['name']} — {r['reason']}" for r in removed) if removed else "нет")

    def _files(self, h, st):
        ti = h.torrent_file()
        if not ti:
            self.files.clear()
            return
        priorities = list(h.get_file_priorities())
        if self._files_key != self.key:
            files = file_list(ti)
            self.files.populate(files, [p > 0 for p in priorities], priorities=priorities, hidden=pad_indices(ti))
            self._files_key = self.key
        self.files.update_progress(list(h.file_progress()), priorities)

    def _files_checked(self):
        h = self.engine.handles.get(self.key)
        if not h:
            return
        current = list(h.get_file_priorities())
        new = [(cur if cur > 0 else 4) if on else 0 for cur, on in zip(current, self.files.checked())]
        if new != current:
            h.prioritize_files(new)

    def _set_priority(self, indices, value):
        h = self.engine.handles.get(self.key)
        if not h or not indices:
            return
        priorities = list(h.get_file_priorities())
        for i in indices:
            priorities[i] = value
        h.prioritize_files(priorities)
        self.files.update_progress(list(h.file_progress()), priorities)

    def _peers(self, h):
        rows = []
        for p in h.get_peer_info():
            ip, port = p.ip
            client = p.client.decode("utf-8", "replace") if isinstance(p.client, bytes) else str(p.client)
            encrypted = bool(p.flags & (p.rc4_encrypted | p.plaintext_encrypted))
            rows.append((f"{ip}:{port}", client, f"{p.progress * 100:.0f}%",
                         fmt_speed(p.payload_down_speed), fmt_speed(p.payload_up_speed),
                         "да" if encrypted else "нет"))
        rows.sort(key=lambda r: r[0])
        _fill(self.peers, rows, right_cols=(2, 3, 4))

    def _trackers(self, h):
        rows = []
        for t in h.trackers():
            msg = t.get("message") or ""
            for ep in t.get("endpoints") or []:
                for ih in (ep.get("info_hashes") or []):
                    err = (ih.get("last_error") or {}).get("value")
                    msg = ih.get("message") or ("ошибка" if err else "работает")
                    break
                break
            if not msg:
                msg = "ожидание" if t.get("updating") else ("работает" if t.get("verified") else "—")
            rows.append((t["url"], t["tier"], msg))
        _fill(self.trackers, rows, right_cols=(1,))

    def _add_tracker(self):
        h = self.engine.handles.get(self.key)
        if not h:
            return
        text, ok = QInputDialog.getMultiLineText(self, "Добавить трекеры", "Адреса трекеров (по одному в строке):")
        if ok:
            for line in text.splitlines():
                if line.strip():
                    h.add_tracker({"url": line.strip()})
            h.force_reannounce()
            self.refresh()
