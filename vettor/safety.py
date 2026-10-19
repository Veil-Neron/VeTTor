"""Выявление лишних и опасных файлов в раздаче до начала загрузки."""
import os
import re
import unicodedata

EXECUTABLE_EXT = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".psm1", ".msi", ".msp", ".mst", ".hta", ".jar", ".lnk",
    ".reg", ".cpl", ".msc", ".scf", ".inf", ".gadget", ".application", ".appx",
    ".appxbundle", ".msix", ".msixbundle", ".appinstaller", ".dll", ".sys", ".chm",
}
MEDIA_EXT = {
    ".mkv", ".mp4", ".avi", ".mov", ".wmv", ".m4v", ".ts", ".m2ts", ".webm", ".flv",
    ".mp3", ".flac", ".wav", ".ogg", ".m4a", ".aac", ".opus", ".ape", ".alac",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp",
    ".pdf", ".epub", ".fb2", ".djvu", ".mobi", ".cbr", ".cbz", ".doc", ".docx", ".txt",
    ".srt", ".ass", ".ssa", ".sub", ".idx", ".vtt",
}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img", ".vhd", ".vhdx", ".cab"}

JUNK, DANGER = "junk", "danger"


def _ext(path):
    return os.path.splitext(path)[1].lower()


def has_bidi_trick(text):
    """Символы управления направлением текста (U+202E и др.) переставляют буквы на экране:
    «film[U+202E]4pm.exe» выглядит как «filmexe.mp4». В именах файлов им делать нечего."""
    return any(unicodedata.category(ch) == "Cf" and unicodedata.bidirectional(ch) in
               ("RLO", "LRO", "RLE", "LRE", "RLI", "LRI", "FSI", "PDF", "PDI") for ch in text)


def _double_extension(path):
    """'film.mp4.exe' и 'film.mp4       .exe' — классическая маскировка вируса под видео."""
    stem, ext = os.path.splitext(os.path.basename(path).lower())
    return ext in EXECUTABLE_EXT and _ext(stem.rstrip(" .\u00a0_-")) in MEDIA_EXT


def is_executable(path):
    return _ext(path) in EXECUTABLE_EXT or has_bidi_trick(path)


def is_risky(path):
    """Файл, который стоит проверить антивирусом после загрузки."""
    return _ext(path) in EXECUTABLE_EXT or _ext(path) in ARCHIVE_EXT or has_bidi_trick(path)


def analyze(files, cfg, hidden=(), symlinks=()):
    """files: список (путь, размер); hidden — индексы служебных файлов,
    symlinks — индексы символических ссылок. Возвращает (метки по файлам, предупреждения)."""
    visible = [f for i, f in enumerate(files) if i not in hidden]
    total = sum(size for _, size in visible) or 1
    media = sum(size for path, size in visible if _ext(path) in MEDIA_EXT)
    mostly_media = media / total > 0.6
    junk_ext = {e.lower() for e in cfg.junk_extensions}
    junk_words = [w.lower() for w in cfg.junk_keywords if w.strip()]

    marks, dangerous, disguised = [], [], []
    for i, (path, size) in enumerate(files):
        if i in hidden:
            marks.append(None)
            continue
        ext = _ext(path)
        name = os.path.basename(path).lower()
        mark = None
        if has_bidi_trick(path) or _double_extension(path):
            mark = DANGER
            disguised.append(os.path.basename(path))
        elif i in symlinks or (mostly_media and ext in EXECUTABLE_EXT):
            mark = DANGER
            dangerous.append(os.path.basename(path))
        elif ext in junk_ext or (ext in {".txt", ".nfo", ".jpg", ".png", ".gif"}
                                 and size < 512 * 1024
                                 and any(w in name for w in junk_words)):
            mark = JUNK
        marks.append(mark)

    warnings = []
    if disguised:
        # Маскировку показываем всегда, даже если предупреждения отключены.
        warnings.append(
            f"Файлы маскируются под другой тип ({_names(disguised)}) — это почти наверняка вирус. "
            "Лучше не загружать эту раздачу."
        )
    if cfg.warn_dangerous and dangerous:
        warnings.append(
            f"Раздача выглядит как медиа, но содержит исполняемые файлы или ссылки ({_names(dangerous)}). "
            "Так часто маскируют вирусы — они не будут загружены, если вы сами их не отметите."
        )
    if cfg.warn_dangerous and len(visible) == 1 and _ext(visible[0][0]) in ARCHIVE_EXT and \
            any(w in visible[0][0].lower() for w in ("film", "фильм", "1080p", "720p", "bdrip", "webrip")):
        warnings.append("Фильм в архиве — подозрительно. Проверьте архив антивирусом перед открытием.")
    return marks, warnings


def _names(names):
    shown = ", ".join(visible_name(n) for n in names[:3])
    return shown + ("…" if len(names) > 3 else "")


def visible_name(name):
    """Показывает скрытые управляющие символы и длинные пробелы, чтобы было видно реальное имя."""
    name = "".join(f"[U+{ord(c):04X}]" if unicodedata.category(c) in ("Cf", "Cc") else c for c in name)
    return re.sub(r"[ \u00a0]{4,}", lambda m: f" [{len(m.group())} пробелов] ", name)


def default_selection(marks, cfg):
    return [not (m == DANGER or (m == JUNK and cfg.skip_junk)) for m in marks]
