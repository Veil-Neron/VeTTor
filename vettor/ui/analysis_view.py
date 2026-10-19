"""Раздел «Проверка файлов»: статический анализ без запуска и без отправки файла."""
import os

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QFileDialog, QFrame, QHBoxLayout, QHeaderView, QLabel, QListWidget,
    QListWidgetItem, QPlainTextEdit, QProgressBar, QPushButton, QTableWidget, QTableWidgetItem,
    QTabWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from ..analysis import report as reports
from ..analysis import worker
from ..analysis.static import STAGES
from ..config import DATA_DIR
from ..util import fmt_size, reveal_in_explorer
from . import theme
from .safe_text import plain_label, warn

SEV_NAMES = {"critical": "критическая", "high": "высокая", "medium": "средняя", "low": "низкая", "info": "к сведению"}
SEV_COLORS = {"critical": "danger", "high": "danger", "medium": "warn", "low": "muted", "info": "muted"}
VERDICT_COLORS = {"malicious": "#ef4444", "high": "#f97316", "review": "#eab308", "low": "#22c55e", "insufficient": "#9ca3af"}


class _Signals(QObject):
    stage = Signal(int, str, str)
    done = Signal(dict)


class _Job(QRunnable):
    def __init__(self, path):
        super().__init__()
        self.path = path
        self.signals = _Signals()

    def run(self):
        r = worker.run(self.path, os.path.join(DATA_DIR, "analysis_work"),
                       lambda s, n, t: self.signals.stage.emit(s, n, t))
        self.signals.done.emit(r)


class DropZone(QFrame):
    fileDropped = Signal(str)

    def __init__(self):
        super().__init__()
        self.setObjectName("DropZone")
        self.setAcceptDrops(True)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        text = QLabel("Перетащите сюда программу, установщик, архив, документ или сценарий")
        text.setObjectName("Muted")
        self.button = QPushButton("Выбрать файл…")
        self.button.setProperty("primary", True)
        lay.addWidget(text, 1)
        lay.addWidget(self.button)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls() and e.mimeData().urls()[0].isLocalFile():
            e.acceptProposedAction()

    def dropEvent(self, e):
        p = e.mimeData().urls()[0].toLocalFile()
        if os.path.isfile(p):
            self.fileDropped.emit(p)


class AnalysisView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(1)
        self.report = None
        self.busy = False

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 12)
        lay.setSpacing(10)
        title = QLabel("Проверка файлов")
        title.setObjectName("Title")
        lay.addWidget(title)
        lay.addWidget(plain_label(
            "Файл проверяется на этом компьютере: он не запускается и никуда не отправляется. Проверяются подпись, "
            "устройство программы, спрятанные команды и адреса, сигнатуры известных угроз и Microsoft Defender. "
            "Проверка поведения в песочнице и по базам VirusTotal будет на следующих этапах.", "Muted"))
        self.drop = DropZone()
        self.drop.button.clicked.connect(self.pick)
        self.drop.fileDropped.connect(self.start)
        lay.addWidget(self.drop)

        # Ход проверки
        prog = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setRange(0, len(STAGES))
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(6)
        self.stage = QLabel("")
        self.stage.setObjectName("Muted")
        prog.addWidget(self.progress, 1)
        prog.addWidget(self.stage)
        lay.addLayout(prog)

        # Итог
        self.card = QFrame()
        self.card.setObjectName("VerdictCard")
        cl = QVBoxLayout(self.card)
        cl.setContentsMargins(16, 12, 16, 12)
        self.v_title = QLabel()
        self.v_title.setStyleSheet("font-size: 16pt; font-weight: 600;")
        self.v_file = plain_label("", "Muted")
        self.v_summary = plain_label()
        self.v_rec = plain_label()
        self.v_note = plain_label("", "Muted")
        for w in (self.v_title, self.v_file, self.v_summary, self.v_rec, self.v_note):
            cl.addWidget(w)
        btns = QHBoxLayout()
        self.b_html = QPushButton("Сохранить отчёт (HTML)")
        self.b_json = QPushButton("Сохранить отчёт (JSON)")
        self.b_folder = QPushButton("Показать файл")
        self.b_html.clicked.connect(lambda: self.export("html"))
        self.b_json.clicked.connect(lambda: self.export("json"))
        self.b_folder.clicked.connect(self._reveal)
        for b in (self.b_html, self.b_json, self.b_folder):
            btns.addWidget(b)
        btns.addStretch(1)
        cl.addLayout(btns)
        self.card.hide()
        lay.addWidget(self.card)

        # Подробности
        self.tabs = QTabWidget()
        self.t_inds = QTreeWidget()
        self.t_inds.setHeaderLabels(["Важность", "Признак", "На чём основано (наблюдения)"])
        self.t_inds.setRootIsDecorated(False)
        self.t_inds.setWordWrap(True)
        self.t_inds.setUniformRowHeights(False)
        self.t_inds.header().setStretchLastSection(False)
        self.t_inds.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.t_inds.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.t_inds.header().setSectionResizeMode(2, QHeaderView.Stretch)
        self.t_info = self._table(["Поле", "Значение"])
        self.t_strings = QPlainTextEdit(readOnly=True)
        self.t_archive = self._table(["Файл в архиве", "Размер", "Оценка"])
        self.t_checks = QPlainTextEdit(readOnly=True)
        hist = QWidget()
        hl = QVBoxLayout(hist)
        hl.setContentsMargins(8, 8, 8, 8)
        self.t_hist = QListWidget()
        self.t_hist.itemDoubleClicked.connect(self._open_history)
        hb = QHBoxLayout()
        b_open = QPushButton("Открыть")
        b_open.clicked.connect(lambda: self._open_history(self.t_hist.currentItem()))
        b_del = QPushButton("Удалить из истории")
        b_del.clicked.connect(self._delete_history)
        hb.addWidget(b_open)
        hb.addWidget(b_del)
        hb.addStretch(1)
        hl.addWidget(self.t_hist)
        hl.addLayout(hb)
        self.tabs.addTab(self.t_inds, "Признаки")
        self.tabs.addTab(self.t_info, "О файле")
        self.tabs.addTab(self.t_strings, "Строки и адреса")
        self.tabs.addTab(self.t_archive, "Архив")
        self.tabs.addTab(self.t_checks, "Проверки и ограничения")
        self.tabs.addTab(hist, "История")
        lay.addWidget(self.tabs, 1)
        self.load_history()

    @staticmethod
    def _table(headers):
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.verticalHeader().hide()
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.setShowGrid(False)
        t.setWordWrap(True)
        t.horizontalHeader().setSectionResizeMode(len(headers) - 1 if len(headers) == 2 else 0, QHeaderView.Stretch)
        for i in range(len(headers)):
            if i != (len(headers) - 1 if len(headers) == 2 else 0):
                t.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeToContents)
        return t

    # ---------- запуск ----------
    def pick(self, start_dir=""):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл для проверки", start_dir or "")
        if path:
            self.start(path)

    def start(self, path):
        if self.busy:
            warn(self, "Проверка файлов", "Дождитесь окончания текущей проверки.")
            return
        self.busy = True
        self.drop.setEnabled(False)
        self.card.hide()
        self.progress.setValue(0)
        self.stage.setText(f"Готовлю проверку: {os.path.basename(path)}")
        job = _Job(os.path.normpath(path))
        job.signals.stage.connect(self._on_stage)
        job.signals.done.connect(self._on_done)
        self.pool.start(job)

    def _on_stage(self, idx, name, text):
        self.progress.setValue(idx + 1)
        self.stage.setText(f"Этап {idx + 1} из {len(STAGES)}: {name}" + (f" — {text}" if text else ""))

    def _on_done(self, report):
        self.busy = False
        self.drop.setEnabled(True)
        self.progress.setValue(len(STAGES))
        self.stage.setText(f"Проверка завершена за {report.get('duration_sec', '—')} с")
        try:
            reports.save(report)
        except OSError:
            pass
        self.show_report(report)
        self.load_history()

    # ---------- показ отчёта ----------
    def show_report(self, r):
        self.report = r
        v, f = r["verdict"], r["file"]
        color = VERDICT_COLORS.get(v["code"], "#9ca3af")
        self.card.setStyleSheet(f"#VerdictCard {{ border-left: 6px solid {color}; border-radius: 8px;"
                                f" background: {theme.current['surface']}; }}")
        self.v_title.setText(f"{v['title']}  ·  уверенность: {v['confidence']}")
        self.v_title.setStyleSheet(f"font-size: 16pt; font-weight: 600; color: {color};")
        self.v_file.setText(f"{f.get('name', '')} · {f.get('type_name', '')} · {fmt_size(f.get('size', 0))}")
        self.v_summary.setText(v["summary"])
        self.v_rec.setText("Рекомендация: " + v["recommendation"])
        self.v_note.setText(v.get("note", ""))
        self.b_folder.setEnabled(bool(f.get("path")) and os.path.exists(f.get("path", "")))
        self.card.show()

        self.t_inds.clear()
        c = theme.current
        for i in r.get("indicators", []):
            it = QTreeWidgetItem([SEV_NAMES.get(i["severity"], i["severity"]), i["title"], "\n".join(i["evidence"])])
            it.setForeground(0, QColor(c[SEV_COLORS.get(i["severity"], "muted")]))
            it.setToolTip(2, "\n".join(i["evidence"]))
            self.t_inds.addTopLevelItem(it)
        if not r.get("indicators"):
            self.t_inds.addTopLevelItem(QTreeWidgetItem(["", "Признаков не обнаружено", ""]))

        rows = [("Имя", f.get("name", "")), ("Тип", f.get("type_name", "")),
                ("Размер", f"{fmt_size(f.get('size', 0))} ({f.get('size', 0)} байт)"),
                ("SHA-256", f.get("sha256", "")), ("SHA-1", f.get("sha1", "")), ("MD5", f.get("md5", ""))]
        sig = r.get("signature") or {}
        if sig.get("status"):
            rows += [("Подпись", sig["status"]), ("Издатель", sig.get("subject", "")),
                     ("Действует до", sig.get("not_after", ""))]
        pe = r.get("pe") or {}
        if pe:
            rows += [("Вид программы", f"{pe.get('kind')} · {pe.get('machine')} · {pe.get('subsystem')}"),
                     (".NET", "да" if pe.get("dotnet") else "нет"), ("Дата сборки", pe.get("compiled", "")),
                     ("Импортировано функций", str(pe.get("imports_count", 0)))]
            rows += [(k, v2) for k, v2 in (pe.get("version") or {}).items()]
            if pe.get("installer"):
                rows.append(("Установщик", pe["installer"]))
        self._fill(self.t_info, rows)

        st = r.get("strings") or {}
        lines = []
        if st.get("urls"):
            lines += ["Адреса в интернете:"] + [f"  {u}" for u in st["urls"]] + [""]
        if st.get("ips"):
            lines += ["IP-адреса:", "  " + ", ".join(st["ips"]), ""]
        for cmd in st.get("commands", []):
            lines += [cmd["title"] + ":"] + [f"  {m}" for m in cmd["matches"]] + [""]
        if pe.get("suspicious_imports"):
            lines += ["Функции Windows, на которые стоит обратить внимание:"]
            lines += [f"  {k}: {', '.join(x)}" for k, x in pe["suspicious_imports"].items()]
        self.t_strings.setPlainText("\n".join(lines) or "Подозрительных адресов и команд не найдено.")

        arc = r.get("archive") or {}
        inner = {s["file"]["name"]: s for s in r.get("inner", [])}
        self._fill(self.t_archive, [(e["name"], fmt_size(e["size"]),
                                     (inner[e["name"]].get("verdict", {}).get("title") or inner[e["name"]].get("skipped", ""))
                                     if e["name"] in inner else "") for e in arc.get("entries", [])])
        self.tabs.setTabEnabled(3, bool(arc))

        checks = [f"{k}: {v2}" for k, v2 in r.get("checks", {}).items()]
        self.t_checks.setPlainText("Выполненные проверки:\n" + "\n".join("  • " + x for x in checks) +
                                   "\n\nОграничения анализа:\n" + "\n".join("  • " + x for x in r.get("limitations", [])))
        self.tabs.setCurrentIndex(0)

    @staticmethod
    def _fill(table, rows):
        table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            for j, val in enumerate(row):
                table.setItem(i, j, QTableWidgetItem(str(val)))
        table.resizeRowsToContents()

    # ---------- история и экспорт ----------
    def load_history(self):
        self.t_hist.clear()
        for path, r in reports.history()[:300]:
            v = r.get("verdict", {})
            it = QListWidgetItem(f"{r.get('started', '').replace('T', ' ')}  ·  {v.get('title', '?')}  ·  {r['file'].get('name', '')}")
            it.setData(Qt.UserRole, path)
            it.setForeground(QColor(VERDICT_COLORS.get(v.get("code"), "#9ca3af")))
            self.t_hist.addItem(it)

    def _open_history(self, item):
        if not item:
            return
        for path, r in reports.history():
            if path == item.data(Qt.UserRole):
                self.show_report(r)
                self.stage.setText("Отчёт из истории")
                return

    def _delete_history(self):
        item = self.t_hist.currentItem()
        if item:
            reports.delete(item.data(Qt.UserRole))
            self.load_history()

    def export(self, kind):
        if not self.report:
            return
        base = os.path.splitext(self.report["file"].get("name", "отчёт"))[0] + " — отчёт о проверке"
        filt = "Веб-страница (*.html)" if kind == "html" else "JSON (*.json)"
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчёт", os.path.join(os.path.expanduser("~"), "Documents",
                                                                                   f"{base}.{kind}"), filt)
        if not path:
            return
        (reports.export_html if kind == "html" else reports.export_json)(self.report, path)
        reveal_in_explorer(path)

    def _reveal(self):
        p = (self.report or {}).get("file", {}).get("path")
        if p and os.path.exists(p):
            reveal_in_explorer(p)
