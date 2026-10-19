"""Защита во время загрузки: каждый докачанный файл проверяется, заражённые удаляются.

Проверяем файл целиком сразу после того, как он докачан и сверен по хэшам, — недокачанный
файл антивирус проверить не может. Найденную угрозу удаляем так, чтобы не пострадали
остальные файлы и сам торрент:
  1. файлу ставится приоритет «не загружать» — заново он не скачается;
  2. торрент ставится на паузу, чтобы libtorrent закрыл файлы (иначе Windows не даст удалить);
  3. файл удаляется, а торрент переподключается со списком кусков без этого файла (см.
     Engine.drop_files) — остальные файлы не перечитываются и раздаются дальше без ошибок."""
import os
from collections import defaultdict

from PySide6.QtCore import QObject, QRunnable, QThreadPool, QTimer, Signal

from . import antivirus, safety
from .engine import TF, has_flag

THREAT = antivirus.THREAT
PE_MAGIC = b"MZ"
DELETE_ATTEMPTS = 10


def disguised_executable(path):
    """Программа Windows внутри файла с расширением видео, музыки или картинки."""
    if os.path.splitext(path)[1].lower() not in safety.MEDIA_EXT:
        return False
    try:
        with open(path, "rb") as f:
            return f.read(2) == PE_MAGIC
    except OSError:
        return False


# Видео, музыка и картинки бывают многогигабайтными — их проверяем быстро, по заголовку.
# Документы (PDF, DOC) могут содержать эксплойты и макросы, поэтому идут в антивирус.
FAST_CHECK_EXT = {
    ".mkv", ".mp4", ".avi", ".mov", ".wmv", ".m4v", ".ts", ".m2ts", ".webm", ".flv",
    ".mp3", ".flac", ".wav", ".ogg", ".m4a", ".aac", ".opus", ".ape", ".alac",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".srt", ".ass", ".ssa", ".sub", ".idx", ".vtt",
}


def needs_antivirus(path):
    return os.path.splitext(path)[1].lower() not in FAST_CHECK_EXT


class _Signals(QObject):
    done = Signal(str, int, str, str, str)  # ключ, индекс, путь, вердикт, причина


class _Check(QRunnable):
    def __init__(self, key, index, path, use_antivirus):
        super().__init__()
        self.key, self.index, self.path, self.use_antivirus = key, index, path, use_antivirus
        self.signals = _Signals()

    def run(self):
        if safety.has_bidi_trick(self.path) or disguised_executable(self.path):
            verdict, reason = THREAT, "программа, замаскированная под другой тип файла"
        elif self.use_antivirus and needs_antivirus(self.path):
            verdict, reason = antivirus.scan(self.path, remediate=False)
            if verdict == THREAT:
                reason = "обнаружен вирус (Microsoft Defender)"
        else:
            verdict, reason = antivirus.CLEAN, ""
        self.signals.done.emit(self.key, self.index, self.path, verdict, reason)


class Guard(QObject):
    removed = Signal(str, str, str)  # ключ, имя файла, причина
    failed = Signal(str, str, str)  # ключ, имя файла, ошибка

    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(1)  # по одному файлу, чтобы не нагружать диск и процессор
        self.pending = defaultdict(list)  # ключ -> [(индекс, путь, причина)]
        self.resume_after = set()
        self.queued = set()
        engine.fileCompleted.connect(self.check_file)
        engine.torrentPaused.connect(self._on_paused)
        engine.fileError.connect(self._on_file_error)

    def check_file(self, key, index):
        if not self.engine.cfg.guard_enabled or (key, index) in self.queued:
            return
        h = self.engine.handles.get(key)
        if not h or h.file_priority(index) == 0:
            return
        path = self.engine.file_path(key, index)
        if not path:
            return
        if not os.path.isfile(path):
            # Докачанный файл уже исчез — его удалил антивирус в реальном времени
            self._vanished(key, index, path, False)
            return
        self.queued.add((key, index))
        job = _Check(key, index, path, antivirus.available())
        job.signals.done.connect(self._on_checked)
        self.pool.start(job)

    def _on_checked(self, key, index, path, verdict, reason):
        self.queued.discard((key, index))
        h = self.engine.handles.get(key)
        if verdict != THREAT or not h:
            return
        h.file_priority(index, 0)
        self.pending[key].append((index, path, reason))
        if has_flag(h.status().flags, TF.paused):
            self._remove(key)
        else:
            self.resume_after.add(key)
            self.engine.pause(key)  # удаление продолжится по событию «торрент на паузе»

    def _on_file_error(self, key, path):
        """libtorrent не нашёл файл (удалён антивирусом посреди загрузки или раздачи)."""
        if not self.engine.cfg.guard_enabled or os.path.exists(path):
            return
        index = self.engine.file_index(key, path)
        h = self.engine.handles.get(key)
        if index is None or not h or h.file_priority(index) == 0 \
                or any(i == index for i, _, _ in self.pending.get(key, [])):
            return  # уже обработан: libtorrent присылает по ошибке на каждый запрошенный кусок
        h.clear_error()
        self._vanished(key, index, path, True)

    def _vanished(self, key, index, path, after_error):
        h = self.engine.handles[key]
        h.file_priority(index, 0)
        self.pending[key].append((index, path, "удалён антивирусом в реальном времени"))
        # После ошибки libtorrent сам ставит торрент на паузу — запускаем его снова
        if after_error or not has_flag(h.status().flags, TF.paused):
            self.resume_after.add(key)
        self._remove(key)

    def _on_paused(self, key):
        if self.pending.get(key):
            # Даём libtorrent мгновение закрыть файлы
            QTimer.singleShot(300, lambda: self._remove(key))

    def _remove(self, key, attempt=0):
        items = self.pending.get(key)
        if not items:
            return
        left, dropped = [], []
        for index, path, reason in items:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass  # уже удалил антивирус в реальном времени
            except OSError as e:
                if attempt < DELETE_ATTEMPTS:
                    left.append((index, path, reason))
                    continue
                self.failed.emit(key, os.path.basename(path), str(e))
                continue
            dropped.append(index)
            self.engine.note_removed(key, os.path.basename(path), reason)
            self.removed.emit(key, os.path.basename(path), reason)
        if left:
            self.pending[key] = left
            QTimer.singleShot(1000, lambda: self._remove(key, attempt + 1))
            return
        self.pending.pop(key, None)
        start = key in self.resume_after
        self.resume_after.discard(key)
        if dropped:
            self.engine.drop_files(key, dropped, start)
        elif start:
            self.engine.resume(key)
