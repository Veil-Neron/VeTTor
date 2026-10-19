"""Распаковка завершённых торрентов с архивами — в фоне, с освобождением места по ходу."""
import os
import time

from PySide6.QtCore import QObject, QRunnable, QThreadPool, QTimer, Signal

from . import antivirus, diskspace, extract
from .engine import TF, downloaded_paths, has_flag, mark_of_the_web

MODES = ("always", "needed", "never")


class _Signals(QObject):
    progress = Signal(str, float)  # ключ, доля 0..1
    done = Signal(str, list, str, bool)  # ключ, папки с результатом, ошибка, архив уже затронут


class _Job(QRunnable):
    def __init__(self, key, sets, cfg):
        super().__init__()
        self.key, self.sets, self.cfg = key, sets, cfg
        self.signals = _Signals()

    def run(self):
        dests, touched = [], False
        total = sum(s.size for s in self.sets) or 1
        base = 0
        try:
            for s in self.sets:
                size = s.size
                last = [0.0]

                def progress(done, _total, base=base, size=size):
                    frac = (base + min(done, size)) / total
                    if frac - last[0] >= 0.005:
                        last[0] = frac
                        self.signals.progress.emit(self.key, frac)

                touched = True  # дальше архив может начать освобождаться
                res = extract.extract(s, self.cfg, progress)
                dests.append(res.dest)
                base += size
                if self.cfg.mark_of_the_web:
                    mark_of_the_web(_all_files(res.dest))
                if self.cfg.compress_extracted:
                    diskspace.compact_folder(res.dest, True)
            if antivirus.available() and self.cfg.guard_enabled:
                for d in dests:
                    antivirus.scan(d, remediate=True)  # найденное Defender сразу отправит в карантин
            self.signals.done.emit(self.key, dests, "", touched)
        except extract.ExtractError as e:
            self.signals.done.emit(self.key, dests, str(e), touched and _consumed(self.sets))
        except Exception as e:  # noqa: BLE001 — любая ошибка должна дойти до пользователя
            self.signals.done.emit(self.key, dests, f"{type(e).__name__}: {e}", touched and _consumed(self.sets))


def _all_files(folder):
    return [os.path.join(r, f) for r, _, files in os.walk(folder) for f in files]


def _consumed(sets):
    """Начала ли распаковка уже освобождать архив (тогда торрент не восстановить без докачки)."""
    for s in sets:
        for p in s.paths:
            if not os.path.exists(p) or diskspace.size_on_disk(p) < os.path.getsize(p):
                return True
    return False


class Unpacker(QObject):
    finished = Signal(str, str, list)  # ключ, имя торрента, папки
    failed = Signal(str, str, str)  # ключ, имя, текст ошибки
    notice = Signal(str)

    def __init__(self, engine, guard):
        super().__init__()
        self.engine, self.guard = engine, guard
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(1)  # по одной распаковке: диск не любит параллельной работы
        self.waiting = {}  # ключ -> время, когда торрент докачался
        self._pending_start = {}  # ключ -> архивы, ждём паузы торрента
        engine.completed.connect(self._on_completed)
        engine.torrentPaused.connect(self._on_paused)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._poll)
        self.timer.start(2000)
        # Распаковка, прерванная закрытием программы
        for key, ex in engine.extras.items():
            if (ex.get("unpack") or {}).get("state") in ("running", "waiting"):
                ex["unpack"] = {"state": "error", "error": "распаковка была прервана закрытием программы"}
        # Торренты, скачанные раньше, автоматически не распаковываем: libtorrent может прислать
        # «торрент завершён» и при запуске программы, а их владелец, возможно, раздаёт архив.
        for key, st in engine.status.items():
            if st.is_finished:
                engine.extras.setdefault(key, {})["unpack_considered"] = True

    # ---------- что и когда распаковывать ----------
    def archives(self, key):
        h = self.engine.handles.get(key)
        if not h:
            return [], []
        paths = [p for p in downloaded_paths(h) if os.path.isfile(p)]
        return extract.find_archives(paths)

    def can_unpack(self, key):
        st = self.engine.status.get(key)
        return bool(st and st.is_finished and not self.engine.unpack_info(key) and self.archives(key)[0])

    def _on_completed(self, key):
        ex = self.engine.extras.setdefault(key, {})
        if ex.get("unpack_considered"):
            return
        ex["unpack_considered"] = True
        if self.engine.cfg.extract_mode != "never":
            self.waiting[key] = time.time()

    def _poll(self):
        for key, since in list(self.waiting.items()):
            if key not in self.engine.handles:
                self.waiting.pop(key)
                continue
            # Ждём, пока защита проверит докачанные файлы
            busy = any(k == key for k, _ in self.guard.queued) or self.guard.pending.get(key)
            if busy or time.time() - since < 3:
                continue
            self.waiting.pop(key)
            self.start(key, automatic=True)

    def start(self, key, automatic=False):
        sets, unsupported = self.archives(key)
        st = self.engine.status.get(key)
        name = st.name if st else key
        if not sets:
            if unsupported and not automatic:
                self.notice.emit(f"«{name}»: архивы 7z распаковывать по ходу нельзя — откройте их архиватором.")
            return False
        if automatic and self.engine.cfg.extract_mode == "needed":
            need_plain = sum(s.size for s in sets) + extract.MARGIN  # обычная распаковка рядом с архивом
            if diskspace.free_space(os.path.dirname(sets[0].paths[0])) >= need_plain:
                return False
        for s in sets:
            if s.kind == "rar" and not extract.unrar_path():
                self.notice.emit(f"«{name}»: для RAR нужен установленный WinRAR — распаковка пропущена.")
                return False
        was_paused = bool(st and has_flag(st.flags, TF.paused))
        self.engine.set_unpack(key, {"state": "waiting", "progress": 0.0})
        self._pending_start[key] = sets
        self.engine.pause(key)  # раздача прекращается: архив будет «съеден» распаковкой
        # Обычно запуск — по событию «торрент на паузе» (libtorrent закрыл файлы);
        # если торрент уже стоял на паузе, события не будет.
        QTimer.singleShot(800 if was_paused else 5000, lambda: self._launch(key))
        return True

    def _on_paused(self, key):
        if key in self._pending_start:
            QTimer.singleShot(500, lambda: self._launch(key))

    def _launch(self, key):
        sets = self._pending_start.pop(key, None)
        if not sets:
            return
        self.engine.set_unpack(key, {"state": "running", "progress": 0.0})
        job = _Job(key, sets, self.engine.cfg)
        job.signals.progress.connect(self._on_progress)
        job.signals.done.connect(self._on_done)
        self.pool.start(job)

    def _on_progress(self, key, frac):
        info = self.engine.unpack_info(key)
        if info:
            info["progress"] = frac

    def _on_done(self, key, dests, error, touched):
        st = self.engine.status.get(key)
        name = st.name if st else key
        if error:
            self.engine.set_unpack(key, {"state": "error", "error": error, "touched": touched})
            hint = (" Часть архива уже освобождена — торрент придётся скачать заново."
                    if touched else " Архив не тронут: торрент можно продолжить раздавать.")
            self.failed.emit(key, name, error + "." + hint)
            if not touched:
                self.engine.set_unpack(key, None)
                self.engine.resume(key)
            return
        # Архивов больше нет — торрент убираем из списка, распакованное остаётся
        self.engine.remove(key, delete_files=False)
        self.finished.emit(key, name, dests)
