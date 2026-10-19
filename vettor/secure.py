"""Шифрование секретов (пароли, API-ключи) через Windows DPAPI.

Зашифрованное значение может расшифровать только эта же учётная запись на этом же
компьютере, поэтому копия settings.json сама по себе ключей не раскрывает."""
import base64
import ctypes
import sys

PREFIX = "dpapi:"

if sys.platform == "win32":
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32
    _UI_FORBIDDEN = 0x1


def _call(fn, data):
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _Blob()
    if not fn(ctypes.byref(blob_in), None, None, None, None, _UI_FORBIDDEN, ctypes.byref(blob_out)):
        raise OSError(ctypes.GetLastError(), "DPAPI")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        _kernel32.LocalFree(blob_out.pbData)


def protect(text):
    if not text or sys.platform != "win32" or text.startswith(PREFIX):
        return text
    return PREFIX + base64.b64encode(_call(_crypt32.CryptProtectData, text.encode("utf-8"))).decode()


def unprotect(value):
    if not value or not value.startswith(PREFIX) or sys.platform != "win32":
        return value or ""
    try:
        return _call(_crypt32.CryptUnprotectData, base64.b64decode(value[len(PREFIX):])).decode("utf-8")
    except (OSError, ValueError):
        return ""  # файл перенесён с другого компьютера или учётной записи
