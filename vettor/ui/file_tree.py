"""Дерево файлов раздачи с галочками, размерами, прогрессом и приоритетами."""
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QHeaderView, QMenu, QTreeWidget, QTreeWidgetItem

from ..safety import DANGER, JUNK, visible_name
from ..util import fmt_size
from . import theme

PRIORITY_NAMES = {0: "Не загружать", 1: "Низкий", 4: "Обычный", 7: "Высокий"}
INDEX_ROLE = Qt.UserRole
SIZE_ROLE = Qt.UserRole + 1


class FileTree(QTreeWidget):
    selectionChangedByUser = Signal()
    priorityRequested = Signal(list, int)

    def __init__(self, show_progress=False, parent=None):
        super().__init__(parent)
        self.show_progress = show_progress
        cols = ["Имя", "Размер"] + (["Прогресс", "Приоритет"] if show_progress else [])
        self.setColumnCount(len(cols))
        self.setHeaderLabels(cols)
        self.header().setSectionResizeMode(0, QHeaderView.Stretch)
        for i in range(1, len(cols)):
            self.header().setSectionResizeMode(i, QHeaderView.ResizeToContents)
        self.header().setStretchLastSection(False)
        self.setUniformRowHeights(True)
        self.file_items = []
        self._building = False
        self.itemChanged.connect(self._on_changed)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._menu)

    def populate(self, files, checked, marks=None, priorities=None, hidden=()):
        """files: [(путь, размер)], checked: [bool], hidden — индексы, которые не показывать."""
        self._building = True
        self.clear()
        self.file_items = [None] * len(files)
        folders = {}
        shown = [(i, p, s) for i, (p, s) in enumerate(files) if i not in hidden]
        single_root = len(shown) > 1 and len({p.replace("\\", "/").split("/")[0] for _, p, _ in shown}) == 1
        for i, path, size in shown:
            parts = path.replace("\\", "/").split("/")
            if single_root:
                parts = parts[1:]
            parent = self.invisibleRootItem()
            prefix = ""
            for part in parts[:-1]:
                prefix += "/" + part
                if prefix not in folders:
                    node = QTreeWidgetItem(parent, [visible_name(part)])
                    node.setFlags(node.flags() | Qt.ItemIsUserCheckable | Qt.ItemIsAutoTristate)
                    folders[prefix] = node
                parent = folders[prefix]
            item = QTreeWidgetItem(parent, [visible_name(parts[-1]), fmt_size(size)])
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setData(0, INDEX_ROLE, i)
            item.setData(0, SIZE_ROLE, size)
            item.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
            item.setCheckState(0, Qt.Checked if checked[i] else Qt.Unchecked)
            if marks and marks[i] == DANGER:
                item.setForeground(0, QColor(theme.current["danger"]))
                item.setToolTip(0, "Исполняемый файл в медиа-раздаче — возможно, вирус")
            elif marks and marks[i] == JUNK:
                item.setForeground(0, QColor(theme.current["muted"]))
                item.setToolTip(0, "Похоже на рекламный или лишний файл")
            if self.show_progress:
                item.setTextAlignment(2, Qt.AlignRight | Qt.AlignVCenter)
                if priorities:
                    item.setText(3, PRIORITY_NAMES.get(priorities[i], str(priorities[i])))
            self.file_items[i] = item
        for prefix, node in folders.items():
            node.setText(1, fmt_size(self._folder_size(node)))
            node.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
        self._building = False
        if len(folders) < 30:
            self.expandAll()

    def _folder_size(self, node):
        total = 0
        for i in range(node.childCount()):
            ch = node.child(i)
            total += ch.data(0, SIZE_ROLE) if ch.data(0, INDEX_ROLE) is not None else self._folder_size(ch)
        return total

    def checked(self):
        return [it is not None and it.checkState(0) == Qt.Checked for it in self.file_items]

    def set_all(self, state):
        self._building = True
        for it in self.file_items:
            if it is not None:
                it.setCheckState(0, Qt.Checked if state else Qt.Unchecked)
        self._building = False
        self.selectionChangedByUser.emit()

    def update_progress(self, progress, priorities):
        self._building = True
        for i, it in enumerate(self.file_items):
            if it is None:
                continue
            size = it.data(0, SIZE_ROLE) or 0
            pct = progress[i] / size * 100 if size else 100
            it.setText(2, f"{pct:.1f}%")
            pr = priorities[i]
            it.setText(3, PRIORITY_NAMES.get(pr, str(pr)))
            want = Qt.Checked if pr > 0 else Qt.Unchecked
            if it.checkState(0) != want:
                it.setCheckState(0, want)
        self._building = False

    def _on_changed(self, item, column):
        if not self._building and column == 0:
            self.selectionChangedByUser.emit()

    def selected_indices(self):
        out = []
        for item in self.selectedItems():
            stack = [item]
            while stack:
                it = stack.pop()
                idx = it.data(0, INDEX_ROLE)
                if idx is not None:
                    out.append(idx)
                stack.extend(it.child(i) for i in range(it.childCount()))
        return sorted(set(out))

    def _menu(self, pos):
        if not self.show_progress or not self.selectedItems():
            return
        menu = QMenu(self)
        for value in (7, 4, 1, 0):
            act = menu.addAction(PRIORITY_NAMES[value])
            act.triggered.connect(lambda _=False, v=value: self.priorityRequested.emit(self.selected_indices(), v))
        menu.exec(self.viewport().mapToGlobal(pos))
