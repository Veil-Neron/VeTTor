"""Работа с местом на диске: освобождение прочитанной части файла, размер на диске, сжатие NTFS."""
import ctypes
import os
import shutil
import subprocess
import sys
from ctypes import wintypes

FSCTL_SET_SPARSE = 0x000900C4
FSCTL_SET_ZERO_DATA = 0x000980C8
GENERIC_WRITE = 0x40000000
SHARE_ALL = 0x1 | 0x2 | 0x4
OPEN_EXISTING = 3
INVALID_HANDLE = ctypes.c_void_p(-1).value
ALIGN = 64 * 1024  # освобождаем целыми блоками по 64 КБ

if sys.platform == "win32":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                 wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _k32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                     ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    _k32.GetCompressedFileSizeW.restype = wintypes.DWORD
    _k32.GetCompressedFileSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]


class _ZeroData(ctypes.Structure):
    _fields_ = [("FileOffset", ctypes.c_longlong), ("BeyondFinalZero", ctypes.c_longlong)]


def release_head(path, end):
    """Освобождает место, занятое первыми `end` байтами файла (файл становится разреженным).
    Размер файла не меняется, прочитанная часть превращается в «дыру» и не занимает диск.
    Возвращает True, если удалось."""
    end -= end % ALIGN
    if end <= 0 or sys.platform != "win32":
        return False
    h = _k32.CreateFileW(path, GENERIC_WRITE, SHARE_ALL, None, OPEN_EXISTING, 0, None)
    if h == INVALID_HANDLE:
        return False
    try:
        ret = wintypes.DWORD()
        if not _k32.DeviceIoControl(h, FSCTL_SET_SPARSE, None, 0, None, 0, ctypes.byref(ret), None):
            return False
        info = _ZeroData(0, end)
        return bool(_k32.DeviceIoControl(h, FSCTL_SET_ZERO_DATA, ctypes.byref(info), ctypes.sizeof(info),
                                         None, 0, ctypes.byref(ret), None))
    finally:
        _k32.CloseHandle(h)


def is_locked(path):
    """Файл открыт другой программой (не даёт открыть себя монопольно)."""
    if sys.platform != "win32":
        return False
    h = _k32.CreateFileW(path, 0x80000000, 0, None, OPEN_EXISTING, 0, None)  # чтение, без совместного доступа
    if h == INVALID_HANDLE:
        return ctypes.get_last_error() == 32  # ERROR_SHARING_VIOLATION
    _k32.CloseHandle(h)
    return False


def size_on_disk(path):
    """Сколько файл или папка реально занимают на диске (с учётом сжатия и «дыр»)."""
    if os.path.isfile(path):
        return _file_on_disk(path)
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            total += _file_on_disk(os.path.join(root, f))
    return total


def _file_on_disk(path):
    if sys.platform != "win32":
        return os.path.getsize(path)
    high = wintypes.DWORD()
    low = _k32.GetCompressedFileSizeW(path, ctypes.byref(high))
    if low == 0xFFFFFFFF and ctypes.get_last_error():
        try:
            return os.path.getsize(path)
        except OSError:
            return 0
    return (high.value << 32) + low


def free_space(path):
    while path and not os.path.exists(path):
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return 0


def compact_folder(path, compress=True, on_file=None):
    """Прозрачное сжатие Windows (LZX) или его отмена. Файлы остаются обычными:
    программы и игры работают как раньше. on_file(count) вызывается по мере обработки.
    Возвращает код завершения compact.exe."""
    args = ["compact.exe", "/c" if compress else "/u", "/s", "/a", "/i", "/exe:lzx" if compress else "/exe",
            os.path.join(path, "*")]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    count = 0
    for line in proc.stdout:
        if b"[OK]" in line or b" = " in line:
            count += 1
            if on_file and count % 50 == 0:
                on_file(count)
    return proc.wait()
