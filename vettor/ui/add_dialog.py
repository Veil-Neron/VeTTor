import os

from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QHBoxLayout, QLabel,
    QPushButton, QVBoxLayout,
)

from .. import diskspace, extract, safety
from ..engine import file_list, pad_indices, symlink_indices
from ..util import fmt_size
from .file_tree import FileTree
from .icons import icon
from .safe_text import plain_label


def banner(text, kind="warn"):
    lbl = plain_label(text)
    lbl.setObjectName("Banner")
    lbl.setProperty("kind", kind)
    lbl.setWordWrap(True)
    return lbl


class AddDialog(QDialog):
    """Выбор папки и файлов перед загрузкой. ti — lt.torrent_info."""

    def __init__(self, cfg, ti, parent=None, save_path=None):
        super().__init__(parent)
        self.cfg = cfg
        self.files = file_list(ti)
        self.pad = pad_indices(ti)
        self.marks, warnings = safety.analyze(self.files, cfg, self.pad, symlink_indices(ti))
        self.setWindowTitle("Добавление торрента")
        self.resize(760, 600)

        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        title = plain_label(safety.visible_name(ti.name()))
        title.setObjectName("Title")
        title.setWordWrap(True)
        lay.addWidget(title)
        size = sum(s for i, (_, s) in enumerate(self.files) if i not in self.pad)
        meta = [f"{len(self.files) - len(self.pad)} файл(ов)", fmt_size(size)]
        if ti.comment():
            meta.append(ti.comment()[:120])
        info = plain_label(" · ".join(meta))
        info.setObjectName("Muted")
        info.setWordWrap(True)
        lay.addWidget(info)
        for w in warnings:
            lay.addWidget(banner(w, "danger"))
        self.archive_size = sum(size for i, (path, size) in enumerate(self.files)
                                if i not in self.pad and extract.find_archives([path])[0])
        if self.archive_size and cfg.extract_mode != "never":
            lay.addWidget(banner(
                "В раздаче архивы. После загрузки VeTTor распакует их и удалит архивы по ходу распаковки, "
                "поэтому дополнительного места почти не понадобится. Раздача после этого прекратится "
                "(это можно изменить в настройках, раздел «Экономия места»).", "info"))
        skipped = sum(1 for m in self.marks if m == safety.JUNK)
        if skipped and cfg.skip_junk:
            lay.addWidget(banner(f"Снята отметка с лишних файлов ({skipped}): ссылки, реклама и т.п. "
                                 "Их можно вернуть галочкой в списке.", "info"))

        # Папка сохранения
        row = QHBoxLayout()
        row.addWidget(QLabel("Сохранить в:"))
        self.path = QComboBox()
        self.path.setEditable(True)
        start_dir = save_path or cfg.download_dir
        for d in [start_dir] + [d for d in cfg.recent_dirs if d != start_dir]:
            self.path.addItem(d)
        row.addWidget(self.path, 1)
        browse = QPushButton(icon("folder"), "")
        browse.setToolTip("Выбрать папку")
        browse.clicked.connect(self._browse)
        row.addWidget(browse)
        lay.addLayout(row)
        self.free = QLabel()
        self.free.setObjectName("Muted")
        lay.addWidget(self.free)
        self.path.currentTextChanged.connect(self._update_summary)

        # Файлы
        self.tree = FileTree()
        self.tree.populate(self.files, safety.default_selection(self.marks, cfg), self.marks, hidden=self.pad)
        self.tree.selectionChangedByUser.connect(self._update_summary)
        lay.addWidget(self.tree, 1)

        tools = QHBoxLayout()
        for text, state in (("Выбрать все", True), ("Снять все", False)):
            b = QPushButton(text)
            b.clicked.connect(lambda _=False, s=state: self.tree.set_all(s))
            tools.addWidget(b)
        tools.addStretch(1)
        self.summary = QLabel()
        self.summary.setObjectName("Muted")
        tools.addWidget(self.summary)
        lay.addLayout(tools)

        opts = QHBoxLayout()
        self.start = QCheckBox("Начать загрузку сразу")
        self.start.setChecked(not cfg.start_paused)
        self.sequential = QCheckBox("Последовательно (для просмотра во время загрузки)")
        opts.addWidget(self.start)
        opts.addWidget(self.sequential)
        opts.addStretch(1)
        lay.addLayout(opts)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        ok = buttons.button(QDialogButtonBox.Ok)
        ok.setText("Добавить")
        ok.setProperty("primary", True)
        buttons.button(QDialogButtonBox.Cancel).setText("Отмена")
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)
        self._update_summary()

    def _browse(self):
        d = QFileDialog.getExistingDirectory(self, "Папка для загрузки", self.path.currentText())
        if d:
            self.path.setCurrentText(os.path.normpath(d))

    def _update_summary(self):
        checked = self.tree.checked()
        size = sum(s for (_, s), c in zip(self.files, checked) if c)
        self.summary.setText(f"Выбрано {sum(checked)} из {len(checked) - len(self.pad)} · {fmt_size(size)}")
        free = diskspace.free_space(self.path.currentText())
        text = f"Свободно на диске: {fmt_size(free)}"
        if free < size:
            text += "  — не хватит места даже для загрузки!"
        elif self.archive_size and self.cfg.extract_mode == "never" and free < size + self.archive_size:
            text += "  — для загрузки хватит, но для распаковки архивов рядом — нет"
        self.free.setText(text)

    def _accept(self):
        if not any(self.tree.checked()):
            self.summary.setText("Отметьте хотя бы один файл")
            return
        path = self.path.currentText().strip()
        try:
            os.makedirs(path, exist_ok=True)
        except OSError:
            self.free.setText("Не удалось создать эту папку")
            return
        self.cfg.remember_dir(path)
        self.accept()

    def result_values(self):
        priorities = [4 if c else 0 for c in self.tree.checked()]
        return self.path.currentText().strip(), priorities, self.start.isChecked(), self.sequential.isChecked()
