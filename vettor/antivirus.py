"""Проверка файлов встроенным антивирусом Windows (Microsoft Defender)."""
import glob
import os
import subprocess
import sys

CLEAN, THREAT, ERROR = "clean", "threat", "error"


def _defender():
    platform = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                            "Microsoft", "Windows Defender", "Platform", "*", "MpCmdRun.exe")
    found = glob.glob(platform)
    if found:
        def version(p):
            parts = os.path.basename(os.path.dirname(p)).split("-")[0].split(".")
            return [int(x) if x.isdigit() else 0 for x in parts]
        return max(found, key=version)
    legacy = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe")
    return legacy if os.path.exists(legacy) else None


def available():
    return sys.platform == "win32" and _defender() is not None


def scan(path, remediate=True):
    """Возвращает (результат, текст). При remediate=True найденные угрозы Defender сам
    отправляет в карантин; при False только сообщает — удалением тогда занимается клиент."""
    exe = _defender()
    if not exe:
        return ERROR, "Microsoft Defender не найден"
    if not os.path.exists(path):
        return ERROR, "Файлы не найдены"
    args = [exe, "-Scan", "-ScanType", "3", "-File", os.path.abspath(path)]
    if not remediate:
        args.append("-DisableRemediation")
    try:
        proc = subprocess.run(
            args,
            capture_output=True, timeout=4 * 3600,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return ERROR, f"Не удалось запустить проверку: {e}"
    if proc.returncode == 0:
        return CLEAN, "Угроз не найдено"
    if proc.returncode == 2:
        return THREAT, ("Найдена угроза! Microsoft Defender поместил её в карантин" if remediate
                        else "Найдена угроза")
    # Defender может быть отключён в пользу другого антивируса
    return ERROR, f"Проверка не выполнена (код {proc.returncode}). Возможно, используется другой антивирус"
