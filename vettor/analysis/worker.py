"""Отдельный процесс анализа: VeTTor.exe --analyze-worker <файл> <отчёт.json> <ход.txt>.

Изоляция от VeTTor: свой процесс, ограничение памяти (Job Object), лимит времени и пониженный
приоритет. Если специально подготовленный файл «подвесит» или «раздует» разбор, будет прерван
только этот процесс."""
import ctypes
import json
import os
import subprocess
import sys
import time
from ctypes import wintypes

MEMORY_LIMIT = 1536 * 1024 * 1024
TIMEOUT = 300


def main(args):
    path, out, prog = args[:3]
    from .static import STAGES, analyze

    def progress(stage, text=""):
        with open(prog, "ab") as f:
            line = json.dumps({"stage": stage, "name": STAGES[stage], "text": text}, ensure_ascii=False) + "\n"
            f.write(line.encode("utf-8"))

    report = analyze(path, progress)
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False)
    os.replace(tmp, out)
    return 0


# ----------------------------- запуск из VeTTor -----------------------------

class _Limits(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD)]


class _IoCounters(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _ExtLimits(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _Limits), ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


def _limit_process(proc):
    """Ограничение памяти; при закрытии VeTTor процесс анализа завершается вместе с ним."""
    if sys.platform != "win32":
        return None
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.OpenProcess.restype = wintypes.HANDLE
    job = k32.CreateJobObjectW(None, None)
    info = _ExtLimits()
    info.BasicLimitInformation.LimitFlags = 0x100 | 0x2000  # PROCESS_MEMORY | KILL_ON_JOB_CLOSE
    info.ProcessMemoryLimit = MEMORY_LIMIT
    k32.SetInformationJobObject(wintypes.HANDLE(job), 9, ctypes.byref(info), ctypes.sizeof(info))
    h = k32.OpenProcess(0x0100 | 0x0001, False, proc.pid)  # SET_QUOTA | TERMINATE
    if h:
        k32.AssignProcessToJobObject(wintypes.HANDLE(job), wintypes.HANDLE(h))
        k32.CloseHandle(wintypes.HANDLE(h))
    return job


def _command(args):
    if getattr(sys, "frozen", False):
        return [sys.executable, "--analyze-worker"] + args
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return [sys.executable, os.path.join(root, "VeTTor.pyw"), "--analyze-worker"] + args


def run(path, workdir, on_progress=lambda stage, name, text: None, should_stop=lambda: False):
    """Запускает анализ в отдельном процессе и возвращает отчёт (dict).
    Если процесс упал или превысил лимиты — отчёт с оценкой «Недостаточно данных»."""
    os.makedirs(workdir, exist_ok=True)
    stamp = f"{os.getpid()}_{int(time.time() * 1000)}"
    out = os.path.join(workdir, f"job_{stamp}.json")
    prog = os.path.join(workdir, f"job_{stamp}.progress")
    open(prog, "w").close()
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "BELOW_NORMAL_PRIORITY_CLASS", 0)
    proc = subprocess.Popen(_command([path, out, prog]), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, creationflags=flags)
    job = _limit_process(proc)
    started, pos, reason = time.time(), 0, ""
    try:
        while proc.poll() is None:
            time.sleep(0.2)
            pos = _read_progress(prog, pos, on_progress)
            if time.time() - started > TIMEOUT:
                reason = "анализ занял больше 5 минут и был прерван (файл может быть специально усложнён)"
            elif should_stop():
                reason = "проверка отменена"
            if reason:
                proc.kill()
                break
        proc.wait()
        _read_progress(prog, pos, on_progress)
        if not reason and os.path.exists(out):
            with open(out, encoding="utf-8") as f:
                return json.load(f)
        if not reason:
            reason = (f"процесс анализа завершился аварийно (код {proc.returncode}) — возможно, превышен лимит "
                      "памяти 1,5 ГБ или файл повредил разборщик")
        return _failed(path, reason)
    finally:
        if job:
            ctypes.windll.kernel32.CloseHandle(wintypes.HANDLE(job))
        for p in (out, prog, out + ".tmp"):
            try:
                os.remove(p)
            except OSError:
                pass


def _read_progress(prog, pos, on_progress):
    try:
        with open(prog, "rb") as f:
            f.seek(pos)
            for line in f:
                if not line.endswith(b"\n"):
                    break  # строка ещё дописывается
                d = json.loads(line.decode("utf-8"))
                on_progress(d["stage"], d["name"], d.get("text", ""))
                pos += len(line)
    except (OSError, ValueError):
        pass
    return pos


def _failed(path, reason):
    from .indicators import decide
    report = {"format": 1, "file": {"name": os.path.basename(path), "path": path,
                                    "size": os.path.getsize(path) if os.path.exists(path) else 0},
              "started": time.strftime("%Y-%m-%dT%H:%M:%S"), "checks": {"Анализ": f"прервано: {reason}"},
              "indicators": [], "error": reason,
              "limitations": ["Анализ не завершился — выводы о файле сделать нельзя."]}
    report["verdict"] = decide(report)
    return report
