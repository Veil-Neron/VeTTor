"""Распаковка скачанных архивов с освобождением места по ходу.

На диске одновременно лежит не «архив + распакованное», а примерно max(архив, распакованное):
  * ZIP и TAR распаковываются здесь же; после каждого файла уже прочитанная часть архива
    освобождается (файл становится разреженным, см. diskspace.release_head), прочитанные
    тома разбитого архива (.zip.001, .tar.002…) удаляются;
  * многотомный RAR распаковывает UnRAR.exe из WinRAR, а каждый пройденный том удаляется;
  * одиночный RAR освободить по ходу нельзя (его читает отдельная программа) — он удаляется
    после распаковки.
Распаковка необратима: освобождённую часть архива уже не вернуть, поэтому перед стартом
проверяется, хватит ли места, а раздача торрента прекращается."""
import os
import re
import subprocess
import tarfile
import threading
import time
import zipfile
from dataclasses import dataclass, field

from . import diskspace, safety

MARGIN = 512 * 1024 * 1024  # запас свободного места
CHUNK = 1024 * 1024
RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
BAD_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')
TAR_EXT = (".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".tbz")
UNSUPPORTED_EXT = (".7z", ".7z.001")


class ExtractError(Exception):
    pass


@dataclass
class ArchiveSet:
    kind: str  # zip | tar | rar
    paths: list  # тома по порядку
    stem: str

    @property
    def size(self):
        return sum(os.path.getsize(p) for p in self.paths if os.path.exists(p))

    @property
    def frees_space(self):
        """Освобождается ли место по ходу распаковки. Одиночный RAR — нет: UnRAR держит его
        открытым без права записи для других, поэтому прочитанную часть не «вырезать»."""
        return self.kind in ("zip", "tar") or len(self.paths) > 1


@dataclass
class Result:
    dest: str
    files: int = 0
    bytes_out: int = 0
    skipped: list = field(default_factory=list)


# ------------------------------- поиск архивов -------------------------------

def find_archives(paths):
    """Группирует файлы торрента в архивы. Возвращает (наборы, неподдерживаемые файлы)."""
    sets, unsupported, used = [], [], set()
    by_lower = {p.lower(): p for p in paths}
    for p in sorted(paths):
        low = p.lower()
        if low in used:
            continue
        name = os.path.basename(low)
        m = re.match(r"^(.*)\.part(\d+)\.rar$", name)
        if m:
            base = m.group(1)
            vols = sorted((q for q in paths if re.match(re.escape(base) + r"\.part\d+\.rar$", os.path.basename(q).lower())
                           and os.path.dirname(q.lower()) == os.path.dirname(low)),
                          key=lambda q: int(re.search(r"\.part(\d+)\.rar$", q.lower()).group(1)))
            used.update(q.lower() for q in vols)
            sets.append(ArchiveSet("rar", vols, os.path.basename(vols[0])[:len(base)]))
        elif name.endswith(".rar"):
            stem = p[:-4]
            old = sorted((by_lower[k] for k in by_lower if re.fullmatch(re.escape(stem.lower()) + r"\.r\d\d", k)),
                         key=lambda q: int(q[-2:]))
            vols = [p] + old
            used.update(q.lower() for q in vols)
            sets.append(ArchiveSet("rar", vols, os.path.basename(stem)))
        elif name.endswith(".zip") or re.search(r"\.(zip|tar)\.\d{3}$", name):
            if re.search(r"\.\d{3}$", name):
                base = p[:-4]
                vols = sorted((by_lower[k] for k in by_lower if re.fullmatch(re.escape(base.lower()) + r"\.\d{3}", k)),
                              key=lambda q: int(q[-3:]))
                kind = "zip" if base.lower().endswith(".zip") else "tar"
                stem = os.path.basename(base)[:-4]
            else:
                vols, kind, stem = [p], "zip", os.path.basename(p)[:-4]
            used.update(q.lower() for q in vols)
            sets.append(ArchiveSet(kind, vols, stem))
        elif name.endswith(TAR_EXT):
            ext = next(e for e in TAR_EXT if name.endswith(e))
            used.add(low)
            sets.append(ArchiveSet("tar", [p], os.path.basename(p)[:-len(ext)]))
        elif name.endswith(UNSUPPORTED_EXT):
            unsupported.append(p)
    return sets, unsupported


# ------------------------------ безопасные пути ------------------------------

def safe_relpath(name):
    """Путь внутри архива → безопасный относительный путь или None (если пытается выйти наружу)."""
    parts = []
    for part in re.split(r"[\\/]+", name):
        if part in ("", "."):
            continue
        if part == "..":
            return None
        part = BAD_CHARS.sub("_", part).rstrip(" .")  # «:» — это и диск C:, и поток NTFS
        if not part:
            continue
        if part.split(".")[0].upper() in RESERVED:
            part = "_" + part
        parts.append(part)
    return os.path.join(*parts) if parts else None


def _target(dest, rel):
    path = os.path.realpath(os.path.join(dest, rel))
    root = os.path.realpath(dest)
    if os.path.commonpath([root, path]) != root:
        raise ExtractError(f"путь выходит за пределы папки: {rel}")
    return path


def _strip_root(names):
    """Если всё лежит в одной папке верхнего уровня — убираем её, чтобы не было «Игра\\Игра»."""
    tops = {n.split(os.sep)[0] for n in names if n}
    if len(tops) == 1 and all(os.sep in n for n in names if n):
        top = tops.pop()
        return lambda n: n[len(top) + 1:]
    return lambda n: n


def pick_dest(archive_set):
    base = os.path.normpath(os.path.join(os.path.dirname(archive_set.paths[0]), archive_set.stem.rstrip(" .") or "Распаковано"))
    dest, i = base, 2
    while os.path.exists(dest) and os.listdir(dest):
        dest = f"{base} ({i})"
        i += 1
    return dest


# ------------------------------ чтение по томам ------------------------------

class MultiFile:
    """Несколько томов как один файл, с освобождением прочитанного."""

    def __init__(self, paths):
        self.paths = paths
        self.sizes = [os.path.getsize(p) for p in paths]
        self.starts = [sum(self.sizes[:i]) for i in range(len(paths))]
        self.total = sum(self.sizes)
        self.pos = 0
        self._idx, self._fh = None, None
        self.released = 0

    def _open(self, idx):
        if self._idx != idx:
            if self._fh:
                self._fh.close()
            self._fh, self._idx = open(self.paths[idx], "rb"), idx
        return self._fh

    def _part(self, pos):
        for i in range(len(self.paths) - 1, -1, -1):
            if pos >= self.starts[i]:
                return i
        return 0

    def seekable(self):
        return True

    def readable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=0):
        self.pos = {0: offset, 1: self.pos + offset, 2: self.total + offset}[whence]
        return self.pos

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.total - self.pos
        out = []
        while n > 0 and self.pos < self.total:
            i = self._part(self.pos)
            if self.pos < self.released:
                raise ExtractError("попытка прочитать уже освобождённую часть архива")
            fh = self._open(i)
            fh.seek(self.pos - self.starts[i])
            chunk = fh.read(min(n, self.starts[i] + self.sizes[i] - self.pos))
            if not chunk:
                raise ExtractError("архив обрывается раньше времени")
            out.append(chunk)
            self.pos += len(chunk)
            n -= len(chunk)
        return b"".join(out)

    def release(self, upto):
        """Освобождает всё до глобального смещения upto: целые тома удаляются, текущий «вырезается»."""
        upto = min(upto, self.total)
        if upto <= self.released:
            return
        for i, p in enumerate(self.paths):
            start, end = self.starts[i], self.starts[i] + self.sizes[i]
            if end <= upto:
                if self._idx == i:
                    self._fh.close()
                    self._fh, self._idx = None, None
                if os.path.exists(p):
                    os.remove(p)
            elif start < upto:
                diskspace.release_head(p, upto - start)
        self.released = upto

    def close(self):
        if self._fh:
            self._fh.close()
            self._fh = None

    def remove_all(self):
        self.close()
        for p in self.paths:
            if os.path.exists(p):
                os.remove(p)


# --------------------------------- оценка места ---------------------------------

def list_contents(archive_set):
    """[(имя, размер)] содержимого архива или None, если заранее не узнать (сжатый tar)."""
    if archive_set.kind == "zip":
        mf = MultiFile(archive_set.paths)
        try:
            with zipfile.ZipFile(mf) as zf:
                return [(i.filename, i.file_size) for i in zf.infolist() if not i.is_dir()]
        except zipfile.BadZipFile as e:
            raise ExtractError(f"архив повреждён: {e}")
        finally:
            mf.close()
    if archive_set.kind == "rar":
        return _rar_list(archive_set.paths[0])
    if archive_set.paths[0].lower().endswith(".tar") or re.search(r"\.tar\.\d{3}$", archive_set.paths[0].lower()):
        mf = MultiFile(archive_set.paths)
        try:
            with tarfile.open(fileobj=mf, mode="r:") as tf:
                return [(m.name, m.size) for m in tf.getmembers() if m.isfile()]
        finally:
            mf.close()
    return None


def space_plan(archive_set, contents):
    """(нужно свободного места сейчас, распакованный размер или None)."""
    archive = archive_set.size
    unpacked = sum(s for _, s in contents) if contents is not None else None
    estimate = unpacked if unpacked is not None else archive * 3  # сжатый tar: оценка с запасом
    if archive_set.frees_space:
        biggest_vol = max(os.path.getsize(p) for p in archive_set.paths)
        # пик: всё распакованное + ещё не освобождённый кусок архива
        extra = biggest_vol if archive_set.kind == "rar" else min(archive, 256 * 1024 * 1024)
        need = max(0, estimate - archive) + extra + MARGIN
    else:
        need = estimate + MARGIN
    return need, unpacked


# ----------------------------------- распаковка -----------------------------------

def extract(archive_set, cfg, progress=None, dest=None):
    """Распаковывает набор, освобождая место. progress(done_bytes, total_bytes)."""
    progress = progress or (lambda d, t: None)
    dest = dest or pick_dest(archive_set)
    contents = list_contents(archive_set)
    if contents is not None:
        need, _ = space_plan(archive_set, contents)
        free = diskspace.free_space(os.path.dirname(dest))
        if free < need:
            raise ExtractError(f"не хватает места: нужно ещё {_gb(need - free)}")
    os.makedirs(dest, exist_ok=True)
    if archive_set.kind == "zip":
        return _extract_zip(archive_set, dest, cfg, progress)
    if archive_set.kind == "tar":
        return _extract_tar(archive_set, dest, cfg, progress)
    return _extract_rar(archive_set, dest, cfg, progress, contents)


def _gb(n):
    return f"{n / 1024 ** 3:.1f} ГБ"


def _skip_set(names_sizes, cfg):
    marks, _ = safety.analyze(names_sizes, cfg)
    return {n for (n, _), m in zip(names_sizes, marks)
            if m == safety.DANGER or (m == safety.JUNK and cfg.skip_junk)}


def _write_stream(src, path, res, on_chunk=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as out:
        n = 0
        while True:
            b = src.read(CHUNK)
            if not b:
                break
            out.write(b)
            res.bytes_out += len(b)
            n += 1
            if on_chunk and n % 32 == 0:
                on_chunk()  # большой файл: освобождаем архив прямо по ходу его записи
    res.files += 1


def _releaser(mf, progress, limit=None):
    """Освобождает уже прочитанную часть архива с запасом на опережающее чтение распаковщика."""
    def run():
        upto = mf.tell() - 8 * CHUNK
        if limit is not None:
            upto = min(upto, limit)
        mf.release(max(0, upto))
        progress(mf.tell(), mf.total)
    return run


def _extract_zip(archive_set, dest, cfg, progress):
    mf = MultiFile(archive_set.paths)
    res = Result(dest)
    try:
        zf = zipfile.ZipFile(mf)
    except zipfile.BadZipFile as e:
        mf.close()
        raise ExtractError(f"архив повреждён: {e}")
    with zf:
        infos = sorted(zf.infolist(), key=lambda i: i.header_offset)
        if any(i.flag_bits & 0x1 for i in infos):
            raise ExtractError("архив защищён паролем")
        cd_start = zf.start_dir
        rels = {i.filename: safe_relpath(i.filename) for i in infos}
        skip = _skip_set([(i.filename, i.file_size) for i in infos if not i.is_dir()], cfg)
        strip = _strip_root([r for r in rels.values() if r])
        for n, info in enumerate(infos):
            rel = rels[info.filename]
            if rel is None or info.filename in skip:
                res.skipped.append(info.filename)
            elif not info.is_dir() and strip(rel):
                with zf.open(info) as src:
                    _write_stream(src, _target(dest, strip(rel)), res, _releaser(mf, progress, cd_start))
            # всё до начала следующего файла больше не понадобится (оглавление в конце не трогаем)
            nxt = infos[n + 1].header_offset if n + 1 < len(infos) else cd_start
            mf.release(min(nxt, cd_start))
            progress(min(nxt, cd_start), mf.total)
    mf.remove_all()
    return res


def _extract_tar(archive_set, dest, cfg, progress):
    mf = MultiFile(archive_set.paths)
    res = Result(dest)
    try:
        # Потоковый режим «r|*»: архив читается строго вперёд, назад не перематывается
        with tarfile.open(fileobj=mf, mode="r|*") as tf:
            release = _releaser(mf, progress)
            for m in tf:
                rel = safe_relpath(m.name)
                if rel is None or not (m.isfile() or m.isdir()):  # ссылки и устройства не распаковываем
                    res.skipped.append(m.name)
                    continue
                if m.isfile():
                    if m.name in _skip_set([(m.name, m.size)], cfg):
                        res.skipped.append(m.name)
                        continue
                    _write_stream(tf.extractfile(m), _target(dest, rel), res, release)
                release()
    except tarfile.TarError as e:
        raise ExtractError(f"архив повреждён: {e}")
    finally:
        mf.close()
    _flatten_single_root(dest)
    mf.remove_all()
    return res


def _flatten_single_root(dest):
    entries = os.listdir(dest)
    if len(entries) == 1 and os.path.isdir(os.path.join(dest, entries[0])):
        inner = os.path.join(dest, entries[0])
        for name in os.listdir(inner):
            os.replace(os.path.join(inner, name), os.path.join(dest, name))
        os.rmdir(inner)


# ------------------------------------- RAR -------------------------------------

def unrar_path():
    for p in (os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "WinRAR", "UnRAR.exe"),
              os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "WinRAR", "UnRAR.exe")):
        if os.path.exists(p):
            return p
    return None


def _run_unrar(args):
    return subprocess.Popen([unrar_path()] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _rar_list(first):
    return [(n, size) for n, size, _ in _rar_entries(first)]


def _rar_entries(first):
    """[(имя, размер, размер в архиве)] файлов архива в порядке хранения. Подписи полей в выводе UnRAR
    зависят от языка, поэтому разбираем по позициям: имя, тип, размер, …, атрибуты."""
    if not unrar_path():
        raise ExtractError("для RAR нужен WinRAR (UnRAR.exe не найден)")
    proc = _run_unrar(["lt", "-v", "-p-", first])
    raw = proc.communicate()[0]
    if proc.returncode not in (0, 1):
        raise ExtractError("архив повреждён или защищён паролем")
    try:
        out = raw.decode("utf-8")
    except UnicodeDecodeError:
        out = raw.decode("cp866", "replace")
    entries, block = [], []
    for line in out.splitlines() + [""]:
        if ":" in line and line.startswith(" "):
            block.append(line.split(":", 1)[1].strip())
        elif not line.strip():
            if len(block) >= 7:
                entries.append(block)
            block = []
    file_type = next((b[1] for b in entries if b[2].isdigit() and int(b[2]) > 0), None)
    items, seen = [], set()
    for b in entries:
        name, kind, size, attrs = b[0], b[1], b[2], b[6]
        if name in seen or not size.isdigit():
            continue  # файл, разбитый на тома, встречается в каждом томе
        seen.add(name)
        is_file = kind == file_type if file_type else "D" not in attrs
        if is_file:
            items.append((name, int(size), int(b[3]) if b[3].isdigit() else 0))
    return items


def _extract_rar(archive_set, dest, cfg, progress, contents):
    """UnRAR отдаёт содержимое всех файлов подряд в поток (команда «p»), а файлы на диске
    создаём сами: так UnRAR не резервирует место под файл заранее, пути и фильтры под
    нашим контролем, а пройденные тома удаляются по ходу."""
    if not unrar_path():
        raise ExtractError("для RAR нужен WinRAR (UnRAR.exe не найден)")
    entries = _rar_entries(archive_set.paths[0])
    contents = [(n, size) for n, size, _ in entries]
    if not contents:
        raise ExtractError("в архиве нет файлов или он защищён паролем")
    res = Result(dest)
    skip = _skip_set(contents, cfg)
    rels = {n: safe_relpath(n) for n, _ in contents}
    strip = _strip_root([r for r in rels.values() if r])
    vols = archive_set.paths
    total = sum(os.path.getsize(v) for v in vols)
    state = {"freed": 0, "run": True}

    def free_passed_volumes():
        # Текущий том — тот, который UnRAR держит открытым; все тома до него уже прочитаны
        while state["run"]:
            time.sleep(0.2)
            idx = next((i for i, v in enumerate(vols) if os.path.exists(v) and diskspace.is_locked(v)), None)
            for v in vols[:idx or 0]:
                if os.path.exists(v):
                    size = os.path.getsize(v)
                    try:
                        os.remove(v)
                        state["freed"] += size
                    except OSError:
                        pass

    proc = subprocess.Popen([unrar_path(), "p", "-inul", "-p-", vols[0]], stdout=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, bufsize=4 * CHUNK,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    packed_done = 0
    cleaner = threading.Thread(target=free_passed_volumes, daemon=True)
    if len(vols) > 1:
        cleaner.start()
    try:
        for name, size, packed in entries:
            rel = rels[name]
            target = None
            if rel is None or name in skip:
                res.skipped.append(name)
            elif strip(rel):
                target = _target(dest, strip(rel))
                os.makedirs(os.path.dirname(target), exist_ok=True)
            out = open(target, "wb") if target else None
            left = size
            try:
                while left > 0:
                    b = proc.stdout.read(min(4 * CHUNK, left))
                    if not b:
                        raise ExtractError("архив повреждён или обрывается раньше времени")
                    if out:
                        out.write(b)
                        res.bytes_out += len(b)
                    left -= len(b)
                progress(state["freed"] + packed_done, total)
            finally:
                if out:
                    out.close()
            if out:
                res.files += 1
            packed_done += packed
        if proc.stdout.read(1):
            raise ExtractError("содержимое архива не совпало со списком файлов")
        code = proc.wait()
    finally:
        state["run"] = False
        if proc.poll() is None:
            proc.kill()
    if code != 0:
        raise ExtractError({3: "архив повреждён (ошибка контрольной суммы)", 11: "архив защищён паролем",
                            5: "ошибка чтения архива"}.get(code, f"UnRAR завершился с кодом {code}"))
    for v in vols:
        if os.path.exists(v):
            os.remove(v)
    progress(total, total)
    return res
