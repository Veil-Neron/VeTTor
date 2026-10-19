"""Статический анализ файла: без запуска и без отправки куда-либо.

Работает в отдельном процессе (см. worker.py): специально подготовленный файл может
«подвесить» разборщик, и тогда пострадает только этот процесс."""
import datetime
import hashlib
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import zipfile

from .. import safety
from .indicators import Indicator, decide

HASH_CHUNK = 4 * 1024 * 1024
MAX_PE_PARSE = 512 * 1024 * 1024
MAX_STRINGS_SCAN = 64 * 1024 * 1024
MAX_YARA = 256 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 5000
MAX_INNER_FILES = 20
MAX_INNER_FILE = 100 * 1024 * 1024
MAX_INNER_TOTAL = 400 * 1024 * 1024
BOMB_RATIO = 200
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

STAGES = ["Приём файла", "Хэши", "Тип и метаданные", "Цифровая подпись", "Разбор содержимого",
          "Строки и индикаторы", "Правила YARA", "Microsoft Defender", "Оценка риска"]

SCRIPT_EXT = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".py", ".sh"}
INNER_INTEREST = safety.EXECUTABLE_EXT | SCRIPT_EXT | {".dll", ".sys", ".msi", ".docm", ".xlsm", ".doc", ".xls", ".pdf", ".lnk"}

# Подозрительные функции Windows: (категория, вес, функции). Многие из них используют и обычные
# программы, поэтому по одной категории вывод не делается — важны сочетания.
API_GROUPS = {
    "injection": ("Внедрение кода в другие процессы", "medium",
                  {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
                   "QueueUserAPC", "SetThreadContext", "NtCreateThreadEx", "RtlCreateUserThread"}),
    "keylog": ("Перехват клавиатуры", "medium", {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
                                                 "GetKeyboardState", "RegisterRawInputDevices"}),
    "antidebug": ("Противодействие отладке", "info", {"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                                                      "NtQueryInformationProcess", "OutputDebugStringA"}),
    "download": ("Загрузка файлов из интернета", "low", {"URLDownloadToFileA", "URLDownloadToFileW",
                                                         "InternetOpenUrlA", "InternetOpenUrlW", "WinHttpOpen",
                                                         "InternetReadFile", "HttpSendRequestA", "HttpSendRequestW"}),
    "execution": ("Запуск других программ", "info", {"CreateProcessA", "CreateProcessW", "ShellExecuteA",
                                                     "ShellExecuteW", "ShellExecuteExW", "WinExec"}),
    "privilege": ("Работа с привилегиями", "info", {"AdjustTokenPrivileges", "LookupPrivilegeValueA",
                                                    "LookupPrivilegeValueW", "OpenProcessToken"}),
    "crypto": ("Шифрование данных", "info", {"CryptEncrypt", "BCryptEncrypt", "CryptGenKey", "CryptAcquireContextW"}),
    "dynamic": ("Динамическая загрузка функций", "info", {"LoadLibraryA", "LoadLibraryW", "GetProcAddress"}),
}

# Опасные команды в строках файла или в сценариях
COMMAND_PATTERNS = [
    ("backup_delete", "high", "Удаление резервных копий Windows (типично для шифровальщиков)",
     r"vssadmin(\.exe)?\s+delete\s+shadows|shadowcopy\s+delete|wbadmin(\.exe)?\s+delete\s+catalog|bcdedit[^\r\n]{0,40}recoveryenabled\s+no"),
    ("defense_off", "high", "Попытка отключить защиту Windows",
     r"Set-MpPreference[^\r\n]{0,60}-Disable|DisableRealtimeMonitoring|DisableAntiSpyware|Add-MpPreference[^\r\n]{0,40}-ExclusionPath|"
     r"netsh(\.exe)?\s+advfirewall\s+set\s+\w+\s+state\s+off"),
    ("download_exec", "medium", "Загрузка и запуск кода из интернета",
     r"DownloadString\s*\(|DownloadFile\s*\(|Net\.WebClient|Invoke-WebRequest|\biwr\s+http|Start-BitsTransfer|"
     r"bitsadmin(\.exe)?\s+/transfer|certutil(\.exe)?\s+-urlcache|mshta(\.exe)?\s+https?://"),
    ("dyn_exec", "medium", "Выполнение динамически собранного кода", r"\bIEX\b|Invoke-Expression|FromBase64String"),
    ("hidden_run", "medium", "Скрытый запуск без окна и в обход политик",
     r"-w(indowstyle)?\s+hidden|-ExecutionPolicy\s+Bypass|-ep\s+bypass|-nop\b"),
    ("persistence", "medium", "Закрепление в автозагрузке",
     r"\\CurrentVersion\\Run(Once)?\b|schtasks(\.exe)?\s+/create|\\Start Menu\\Programs\\Startup|New-ScheduledTask"),
    ("log_wipe", "high", "Очистка журналов Windows (заметание следов)", r"wevtutil(\.exe)?\s+cl\b|Clear-EventLog"),
    ("vm_check", "low", "Проверки на виртуальную машину или песочницу",
     r"VBoxService|VBoxTray|vmtoolsd|SbieDll\.dll|wine_get_unix_file_name|VMware Tools|qemu-ga"),
    ("credentials", "high", "Обращение к сохранённым паролям и кошелькам",
     r"\\Login Data\b|logins\.json|wallet\.dat|\\Telegram Desktop\\tdata|key4\.db"),
]

class TruncatedFile(Exception):
    pass


SEVERITY_WORD = {"info": "к сведению", "low": "низкая", "medium": "средняя", "high": "высокая", "critical": "критическая"}


def analyze(path, progress=lambda stage, text="": None, defender=True, depth=0, display_name=None):
    started = datetime.datetime.now()
    report = {
        "format": 1,
        "file": {"name": display_name or os.path.basename(path), "path": path},
        "started": started.isoformat(timespec="seconds"),
        "checks": {},
        "indicators": [],
        "limitations": [],
    }
    inds = []

    def check(name, state):
        report["checks"][name] = state

    # 1. Приём
    progress(0)
    try:
        st = os.stat(path)
    except OSError as e:
        report["error"] = f"файл недоступен: {e}"
        return _finish(report, inds, started)
    size = st.st_size
    report["file"]["size"] = size
    check("Приём файла", "выполнено")
    for ind in _name_checks(report["file"]["name"]):
        inds.append(ind)

    # 2. Хэши
    progress(1)
    report["file"].update(_hashes(path))
    check("Хэши", "выполнено")

    # 3. Тип
    progress(2)
    with open(path, "rb") as f:
        head = f.read(4096)
    kind = _detect(head, report["file"]["name"])
    report["file"]["type"] = kind
    report["file"]["type_name"] = TYPE_NAMES.get(kind, kind)
    check("Тип и метаданные", "выполнено")
    ext = os.path.splitext(report["file"]["name"])[1].lower()
    if kind == "pe" and ext and ext not in (".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".efi", ".msi", ".drv", ".mui", ".pyd", ".tmp"):
        inds.append(Indicator("pe_disguised", "high", f"Программа Windows под видом файла «{ext}»",
                              [f"содержимое начинается с подписи MZ (программа), а расширение — {ext}"],
                              "маскировка"))

    # 4. Подпись
    progress(3)
    if kind in ("pe", "msi") or ext in (".ps1", ".psm1", ".vbs", ".js", ".msi", ".cab", ".cat"):
        sig = _signature(path)
        report["signature"] = sig
        check("Цифровая подпись", "выполнено" if "status" in sig else f"ошибка: {sig.get('error')}")
        inds += _signature_indicators(sig)
    else:
        check("Цифровая подпись", "не применяется к этому типу")

    # 5. Разбор
    progress(4)
    try:
        if kind == "pe":
            if size > MAX_PE_PARSE:
                check("Разбор содержимого", "пропущено: файл слишком большой")
                report["limitations"].append("Программа больше 512 МБ — её структура не разбиралась.")
            else:
                report["pe"], pe_inds = _analyze_pe(path, report.get("signature"))
                inds += pe_inds
                check("Разбор содержимого", "выполнено")
        elif kind in ("zip", "ooxml", "rar", "7z", "tar", "gzip"):
            report["archive"], arc_inds, inner = _analyze_archive(path, kind, progress, depth)
            inds += arc_inds
            report["inner"] = inner
            check("Разбор содержимого", "выполнено")
        elif kind == "ole":
            inds += _analyze_ole(path)
            check("Разбор содержимого", "выполнено")
        elif kind == "pdf":
            inds += _analyze_pdf(path)
            check("Разбор содержимого", "выполнено")
        elif kind == "script":
            check("Разбор содержимого", "выполнено (сценарий)")
        else:
            check("Разбор содержимого", "нет отдельного разбора для этого типа")
    except TruncatedFile as e:
        check("Разбор содержимого", f"ошибка: {e}")
        inds.append(Indicator("truncated", "low", "Файл обрезан или повреждён", [str(e)], "структура"))
        report["limitations"].append("Файл повреждён — его содержимое проверено не полностью.")
    except Exception as e:  # noqa: BLE001 — повреждённый файл не должен ронять анализ
        check("Разбор содержимого", f"ошибка: {type(e).__name__}: {e}")
        inds.append(Indicator("parse_error", "low", "Структура файла повреждена или нестандартна",
                              [f"{type(e).__name__}: {e}"], "структура"))

    # 6. Строки
    progress(5)
    strings_info, str_inds = _strings_and_iocs(path, kind, size)
    report["strings"] = strings_info
    inds += str_inds
    check("Строки и индикаторы", "выполнено" if size <= MAX_STRINGS_SCAN else "частично: просмотрены первые 64 МБ")
    if size > MAX_STRINGS_SCAN:
        report["limitations"].append("Строки искались только в первых 64 МБ файла.")

    # 7. YARA
    progress(6)
    yara_matches, y_inds, y_state = _yara(path, size)
    report["yara"] = yara_matches
    inds += y_inds
    check("Правила YARA", y_state)

    # 8. Defender
    progress(7)
    if defender:
        from .. import antivirus
        if antivirus.available():
            result, text = antivirus.scan(path, remediate=False)
            report["defender"] = {"result": result, "text": text}
            check("Microsoft Defender", "выполнено" if result != antivirus.ERROR else f"ошибка: {text}")
            if result == antivirus.THREAT:
                inds.append(Indicator("defender", "critical", "Microsoft Defender обнаружил угрозу",
                                      [text], "антивирус"))
        else:
            check("Microsoft Defender", "недоступен (возможно, используется другой антивирус)")
    else:
        check("Microsoft Defender", "не выполнялся для вложенного файла (проверен архив целиком)")

    progress(8)
    return _finish(report, inds, started)


def _finish(report, inds, started):
    report["indicators"] = [i.to_dict() for i in _dedupe(inds)]
    report["verdict"] = decide(report)
    report["finished"] = datetime.datetime.now().isoformat(timespec="seconds")
    report["duration_sec"] = round((datetime.datetime.now() - started).total_seconds(), 1)
    report["limitations"] += [
        "Файл не запускался: поведение программы (что она делает при запуске) не проверялось — "
        "это будет на этапе песочницы.",
        "Репутационные базы (VirusTotal и др.) не запрашивались — это следующий этап.",
        "Отсутствие найденных угроз не гарантирует, что файл безопасен.",
    ]
    return report


def _dedupe(inds):
    seen, out = {}, []
    for i in inds:
        if i.id in seen:
            seen[i.id].evidence += [e for e in i.evidence if e not in seen[i.id].evidence][:5]
            continue
        seen[i.id] = i
        out.append(i)
    return out


# ------------------------------------- приём и тип -------------------------------------

TYPE_NAMES = {
    "pe": "Программа Windows (PE)", "msi": "Установщик Windows (MSI)", "zip": "Архив ZIP",
    "ooxml": "Документ Office (DOCX/XLSX/PPTX)", "rar": "Архив RAR", "7z": "Архив 7z", "tar": "Архив TAR",
    "gzip": "Сжатый файл GZIP", "ole": "Документ Office старого формата (DOC/XLS)", "pdf": "Документ PDF",
    "lnk": "Ярлык Windows", "script": "Сценарий (скрипт)", "elf": "Программа Linux (ELF)",
    "text": "Текстовый файл", "unknown": "Неизвестный тип",
}


def _detect(head, name):
    ext = os.path.splitext(name)[1].lower()
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        return "ooxml" if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".dotm") else "zip"
    if head[:7] == b"Rar!\x1a\x07\x00" or head[:8] == b"Rar!\x1a\x07\x01\x00":
        return "rar"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:4] == b"\xd0\xcf\x11\xe0":
        return "msi" if ext in (".msi", ".msp") else "ole"
    if head[:4] == b"%PDF":
        return "pdf"
    if head[:4] == b"L\x00\x00\x00":
        return "lnk"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if len(head) > 262 and head[257:262] == b"ustar":
        return "tar"
    if head[:4] == b"\x7fELF":
        return "elf"
    if ext in SCRIPT_EXT:
        return "script"
    if head and sum(32 <= b < 127 or b in (9, 10, 13) for b in head) / len(head) > 0.9:
        return "text"
    return "unknown"


def _hashes(path):
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    with open(path, "rb") as f:
        while True:
            b = f.read(HASH_CHUNK)
            if not b:
                break
            sha256.update(b)
            sha1.update(b)
            md5.update(b)
    return {"sha256": sha256.hexdigest(), "sha1": sha1.hexdigest(), "md5": md5.hexdigest()}


def _name_checks(name):
    out = []
    if safety.has_bidi_trick(name):
        out.append(Indicator("name_bidi", "high", "В имени файла спрятаны символы, переставляющие буквы",
                             [f"имя: {safety.visible_name(name)}"], "маскировка"))
    if safety._double_extension(name):
        out.append(Indicator("name_double_ext", "high", "Двойное расширение: программа под видом медиафайла",
                             [f"имя: {safety.visible_name(name)}"], "маскировка"))
    return out


def _entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


# ------------------------------------- подпись -------------------------------------

def _signature(path):
    script = (
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        "$s=Get-AuthenticodeSignature -LiteralPath $env:VETTOR_SIG_PATH;"
        "[pscustomobject]@{status=[string]$s.Status;message=[string]$s.StatusMessage;"
        "type=[string]$s.SignatureType;subject=[string]$s.SignerCertificate.Subject;"
        "issuer=[string]$s.SignerCertificate.Issuer;"
        "not_after=$(if($s.SignerCertificate){$s.SignerCertificate.NotAfter.ToString('yyyy-MM-dd')}else{''});"
        "timestamp=[string]$s.TimeStamperCertificate.Subject} | ConvertTo-Json -Compress")
    env = dict(os.environ, VETTOR_SIG_PATH=path)
    try:
        out = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                             capture_output=True, timeout=60, env=env, creationflags=NO_WINDOW)
        data = json.loads(out.stdout.decode("utf-8", "replace").strip() or "{}")
        return data if data.get("status") else {"error": out.stderr.decode("utf-8", "replace")[:200] or "нет ответа"}
    except (OSError, subprocess.TimeoutExpired, ValueError) as e:
        return {"error": str(e)}


def _publisher(subject):
    m = re.search(r"CN=(\"[^\"]+\"|[^,]+)", subject or "")
    return m.group(1).strip('"') if m else (subject or "")


def _signature_indicators(sig):
    st = sig.get("status")
    if not st:
        return []
    pub = _publisher(sig.get("subject"))
    if st == "Valid":
        return [Indicator("sig_valid", "info", f"Подписан: {pub}",
                          [f"цифровая подпись действительна, издатель {pub}"], "подпись", weight=-3)]
    if st == "NotSigned":
        return [Indicator("sig_none", "low", "Нет цифровой подписи",
                          ["у файла нет цифровой подписи — так бывает и у безобидных программ"], "подпись")]
    if st == "HashMismatch":
        return [Indicator("sig_broken", "high", "Подпись не совпадает с файлом: его изменили после подписания",
                          [sig.get("message", "")], "подпись")]
    return [Indicator("sig_untrusted", "medium", f"Подпись недоверенная ({st})",
                      [sig.get("message", ""), f"издатель: {pub}"], "подпись")]


# ------------------------------------- программы Windows -------------------------------------

PACKER_SECTIONS = {"upx0": "UPX", "upx1": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".petite": "Petite",
                   ".nsp0": "NsPack", "mpress1": "MPRESS", ".themida": "Themida", ".vmp0": "VMProtect",
                   ".vmp1": "VMProtect", ".enigma1": "Enigma", ".mpress1": "MPRESS"}


def _analyze_pe(path, sig):
    import pefile

    inds = []
    pe = pefile.PE(path, fast_load=True)
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
        ])
        info = {
            "machine": {0x14c: "x86 (32 бита)", 0x8664: "x64 (64 бита)", 0xaa64: "ARM64"}.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
            "kind": "DLL" if pe.is_dll() else ("Драйвер" if pe.is_driver() else "Программа"),
            "subsystem": {2: "оконная", 3: "консольная", 1: "драйвер"}.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem)),
            "dotnet": pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0,
        }
        ts = pe.FILE_HEADER.TimeDateStamp
        try:
            info["compiled"] = datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d") if ts else ""
        except (OverflowError, OSError, ValueError):
            info["compiled"] = ""

        # Секции, упаковка
        sections = []
        packers = set()
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
            ent = round(s.get_entropy(), 2)
            ch = s.Characteristics
            execu, write = bool(ch & 0x20000000), bool(ch & 0x80000000)
            sections.append({"name": name, "virtual_size": s.Misc_VirtualSize, "raw_size": s.SizeOfRawData,
                             "entropy": ent, "exec": execu, "write": write})
            if name.lower() in PACKER_SECTIONS:
                packers.add(PACKER_SECTIONS[name.lower()])
            if execu and write:
                inds.append(Indicator("pe_wx", "medium", "Секция одновременно исполняемая и записываемая",
                                      [f"секция {name}: исполнение + запись (так часто распаковывается вирусный код)"],
                                      "структура"))
            if execu and ent > 7.2 and s.SizeOfRawData > 4096:
                inds.append(Indicator("pe_entropy", "medium", "Код зашифрован или упакован",
                                      [f"секция {name}: энтропия {ent} из 8 (у обычного кода 5–6.5)"], "упаковка"))
        info["sections"] = sections
        file_size = os.path.getsize(path)
        cut = [s.Name.rstrip(b"\x00").decode("latin-1", "replace") for s in pe.sections
               if s.SizeOfRawData and s.PointerToRawData + s.SizeOfRawData > file_size]
        if cut or not pe.sections:
            raise TruncatedFile("файл обрезан или повреждён: данных секций " + (", ".join(cut) or "нет") +
                                f" нет в файле ({file_size} байт)")
        if packers:
            info["packers"] = sorted(packers)
            protectors = packers & {"Themida", "VMProtect", "Enigma"}
            inds.append(Indicator("pe_packer", "medium" if protectors else "low",
                                  "Защищён протектором " + ", ".join(sorted(packers)) if protectors
                                  else "Сжат упаковщиком " + ", ".join(sorted(packers)),
                                  [f"секции упаковщика: {', '.join(sorted(packers))}",
                                   "упаковщики используют и обычные программы — сам по себе это не признак заражения"],
                                  "упаковка"))

        # Импорты
        imports, funcs = {}, set()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:500]:
            dll = entry.dll.decode("latin-1", "replace").lower()
            names = [imp.name.decode("latin-1", "replace") for imp in entry.imports[:2000] if imp.name]
            imports[dll] = names
            funcs.update(names)
        info["imports_count"] = len(funcs)
        info["import_dlls"] = sorted(imports)
        hits = {}
        for key, (title, sev, group) in API_GROUPS.items():
            found = sorted(funcs & group)
            if found:
                hits[key] = found
        info["suspicious_imports"] = {API_GROUPS[k][0]: v for k, v in hits.items()}
        if {"VirtualAllocEx", "WriteProcessMemory"} <= funcs and funcs & {"CreateRemoteThread", "NtCreateThreadEx",
                                                                         "QueueUserAPC", "SetThreadContext"}:
            inds.append(Indicator("api_injection_combo", "high", "Набор функций для внедрения кода в чужие процессы",
                                  [", ".join(sorted(hits.get("injection", [])))], "поведение (по импортам)"))
        for key, found in hits.items():
            title, sev, _ = API_GROUPS[key]
            if sev in ("low", "medium") and key != "injection":
                inds.append(Indicator(f"api_{key}", sev, title, [", ".join(found)], "поведение (по импортам)"))
        if not info["dotnet"] and len(funcs) < 10 and {"LoadLibraryA", "GetProcAddress"} & funcs | {"LoadLibraryW"} & funcs:
            inds.append(Indicator("pe_few_imports", "low", "Почти нет импортов — функции подгружаются скрытно",
                                  [f"импортировано функций: {len(funcs)}"], "упаковка"))
        if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            inds.append(Indicator("pe_tls", "info", "Код запускается до основной программы (TLS)",
                                  ["есть TLS-обработчики; их используют и для защиты от отладки"], "структура"))

        # Сведения о версии и самозванство
        ver = _version_info(pe)
        info["version"] = ver
        company = (ver.get("CompanyName") or "").lower()
        signer = _publisher((sig or {}).get("subject")).lower()
        if "microsoft" in company and (sig or {}).get("status") in ("NotSigned", "HashMismatch") and "microsoft" not in signer:
            inds.append(Indicator("pe_impostor", "high", "Выдаёт себя за программу Microsoft, но не подписан Microsoft",
                                  [f"в сведениях о файле: {ver.get('CompanyName')}", f"подпись: {(sig or {}).get('status')}"],
                                  "маскировка"))
        orig = (ver.get("OriginalFilename") or "").lower()
        if orig in ("svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "explorer.exe", "services.exe", "smss.exe"):
            inds.append(Indicator("pe_system_name", "medium", f"Называет себя системным файлом Windows ({orig})",
                                  [f"OriginalFilename = {ver.get('OriginalFilename')}"], "маскировка"))

        # Хвост (overlay) и вложенные программы
        overlay = pe.get_overlay_data_start_offset()
        size = os.path.getsize(path)
        if overlay and size - overlay > 1024 * 1024:
            info["overlay"] = size - overlay
        with open(path, "rb") as f:
            blob = f.read(min(size, MAX_STRINGS_SCAN))
        installer = next((n for marker, n in ((b"Nullsoft", "NSIS"), (b"Inno Setup", "Inno Setup"),
                                              (b"InstallShield", "InstallShield"), (b"WixBurn", "WiX"),
                                              (b"7zS.sfx", "7-Zip SFX"), (b"RarSFX", "WinRAR SFX")) if marker in blob), None)
        if installer:
            info["installer"] = installer
            inds.append(Indicator("pe_installer", "info", f"Установщик {installer}",
                                  ["программы внутри установщика сжаты, их содержимое статическим анализом не видно"],
                                  "структура"))
        embedded = blob.count(b"This program cannot be run in DOS mode")
        if embedded > 1 and not installer:
            inds.append(Indicator("pe_embedded", "medium", "Внутри файла спрятана ещё одна программа",
                                  [f"найдено заголовков программ: {embedded}"], "структура"))
        return info, inds
    finally:
        pe.close()


def _version_info(pe):
    out = {}
    try:
        for fi in getattr(pe, "FileInfo", []) or []:
            for entry in fi:
                for st in getattr(entry, "StringTable", []) or []:
                    for k, v in st.entries.items():
                        key = k.decode("latin-1", "replace")
                        if key in ("CompanyName", "ProductName", "FileDescription", "OriginalFilename",
                                   "FileVersion", "LegalCopyright", "InternalName"):
                            out[key] = v.decode("utf-8", "replace")[:200]
    except Exception:  # noqa: BLE001 — сведения о версии необязательны
        pass
    return out


# ------------------------------------- документы -------------------------------------

def _analyze_ole(path):
    with open(path, "rb") as f:
        data = f.read(MAX_STRINGS_SCAN)
    inds = []
    if b"_VBA_PROJECT" in data or b"Attribute VB_Name" in data or b"VBA" in data and b"PROJECT" in data:
        auto = [n for n in (b"AutoOpen", b"Document_Open", b"Workbook_Open", b"Auto_Open") if n in data]
        inds.append(Indicator("doc_macro", "high" if auto else "medium",
                              "Документ содержит макросы" + (", запускающиеся при открытии" if auto else ""),
                              [", ".join(a.decode() for a in auto)] if auto else ["найден проект VBA"], "документ"))
    return inds


def _analyze_ooxml(zf):
    inds = []
    names = [i.filename for i in zf.infolist()[:MAX_ARCHIVE_ENTRIES]]
    if any(n.lower().endswith("vbaproject.bin") for n in names):
        inds.append(Indicator("doc_macro", "medium", "Документ содержит макросы", ["найден vbaProject.bin"], "документ"))
    for n in names:
        if n.endswith(".rels"):
            try:
                with zf.open(n) as f:
                    rels = f.read(1024 * 1024).decode("utf-8", "replace")
            except (zipfile.BadZipFile, OSError, RuntimeError):
                continue
            ext = re.findall(r'Target="(https?://[^"]+)"[^>]*TargetMode="External"', rels)
            if ext and "attachedTemplate" in rels:
                inds.append(Indicator("doc_remote_template", "high", "Документ подгружает шаблон из интернета",
                                      ext[:3], "документ"))
    return inds


def _analyze_pdf(path):
    with open(path, "rb") as f:
        data = f.read(MAX_STRINGS_SCAN)
    inds = []
    found = {k: data.count(k.encode()) for k in ("/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile")}
    if found["/Launch"]:
        inds.append(Indicator("pdf_launch", "high", "PDF пытается запустить программу", ["/Launch"], "документ"))
    if found["/JavaScript"] or found["/JS"]:
        auto = found["/OpenAction"] or found["/AA"]
        inds.append(Indicator("pdf_js", "medium" if auto else "low",
                              "PDF содержит JavaScript" + (", выполняемый при открытии" if auto else ""),
                              [f"{k}: {v}" for k, v in found.items() if v], "документ"))
    if found["/EmbeddedFile"]:
        inds.append(Indicator("pdf_embedded", "low", "В PDF вложены файлы", [f"вложений: {found['/EmbeddedFile']}"], "документ"))
    return inds


# ------------------------------------- архивы -------------------------------------

def _list_archive(path, kind):
    """[(имя, размер, сжатый размер или None, зашифрован)]"""
    if kind in ("zip", "ooxml"):
        with zipfile.ZipFile(path) as zf:
            return [(i.filename, i.file_size, i.compress_size, bool(i.flag_bits & 1))
                    for i in zf.infolist()[:MAX_ARCHIVE_ENTRIES] if not i.is_dir()]
    if kind == "rar":
        from .. import extract
        return [(n, s, p, False) for n, s, p in extract._rar_entries(path)[:MAX_ARCHIVE_ENTRIES]]
    # 7z, tar, gzip — встроенный в Windows tar (libarchive) умеет их читать из файла
    tar = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "tar.exe")
    out = subprocess.run([tar, "-tvf", path], capture_output=True, timeout=120, creationflags=NO_WINDOW)
    items = []
    for line in out.stdout.decode("utf-8", "replace").splitlines()[:MAX_ARCHIVE_ENTRIES]:
        m = re.match(r"^\S+\s+\S+\s+\S+\s+\S+\s+(\d+)\s+\S+\s+\S+\s+\S+\s+(.+)$", line)
        if m and not line.startswith("d"):
            items.append((m.group(2), int(m.group(1)), None, False))
    return items


def _read_inner(path, kind, name, limit):
    """Читает файл из архива целиком, но не больше limit байт (защита от «бомб»)."""
    if kind in ("zip", "ooxml"):
        with zipfile.ZipFile(path) as zf, zf.open(name) as f:
            data = f.read(limit + 1)
    else:
        if kind == "rar":
            from .. import extract
            cmd = [extract.unrar_path(), "p", "-inul", "-p-", path, name]
        else:
            cmd = [os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "tar.exe"), "-xOf", path, name]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=NO_WINDOW)
        data = proc.stdout.read(limit + 1)
        proc.kill()
        proc.wait()
    if len(data) > limit:
        raise ValueError("файл в архиве больше допустимого для проверки размера")
    return data


def _analyze_archive(path, kind, progress, depth):
    inds = []
    info = {"entries": [], "total_unpacked": 0}
    if kind == "ooxml":
        with zipfile.ZipFile(path) as zf:
            inds += _analyze_ooxml(zf)
    if kind == "gzip":
        return info, inds, []
    items = _list_archive(path, kind)
    info["entries"] = [{"name": n, "size": s} for n, s, _, _ in items[:500]]
    info["count"] = len(items)
    total = sum(s for _, s, _, _ in items)
    info["total_unpacked"] = total
    size = os.path.getsize(path)
    if any(enc for *_, enc in items):
        inds.append(Indicator("arc_password", "medium", "Архив защищён паролем — содержимое проверить нельзя",
                              ["так часто прячут вирусы от антивирусов"], "архив"))
    if size and total / size > BOMB_RATIO and total > 1024 ** 3:
        inds.append(Indicator("arc_bomb", "high", "Архив-«бомба»: при распаковке займёт огромный объём",
                              [f"сжато {size} байт → распакуется в {total} байт (в {total // size} раз больше)"], "архив"))
    marks, _ = safety.analyze([(n, s) for n, s, _, _ in items], _SafetyCfg())
    for (n, s, _, _), m in zip(items, marks):
        if m == safety.DANGER:
            inds.append(Indicator("arc_dangerous_file", "high", "В архиве замаскированная или неуместная программа",
                                  [safety.visible_name(n)], "архив"))
    inner = []
    if depth >= 1 or kind == "ooxml":
        return info, inds, inner
    budget = MAX_INNER_TOTAL
    candidates = [(n, s) for n, s, _, enc in items if not enc and os.path.splitext(n)[1].lower() in INNER_INTEREST]
    if len(candidates) > MAX_INNER_FILES:
        inds.append(Indicator("arc_many_exec", "info", "В архиве много программ",
                              [f"подробно проверены первые {MAX_INNER_FILES} из {len(candidates)}"], "архив"))
    tmp = tempfile.mkdtemp(prefix="vettor_inner_")
    try:
        for n, s in candidates[:MAX_INNER_FILES]:
            if s > MAX_INNER_FILE or s > budget:
                inner.append({"file": {"name": n, "size": s}, "skipped": "слишком большой для проверки"})
                continue
            progress(4, f"проверяю файл в архиве: {os.path.basename(n)}")
            try:
                data = _read_inner(path, kind, n, MAX_INNER_FILE)
            except Exception as e:  # noqa: BLE001
                inner.append({"file": {"name": n, "size": s}, "skipped": f"не удалось извлечь: {e}"})
                continue
            budget -= len(data)
            p = os.path.join(tmp, "inner_" + hashlib.sha256(n.encode("utf-8", "replace")).hexdigest()[:12])
            with open(p, "wb") as f:
                f.write(data)
            sub = analyze(p, defender=False, depth=depth + 1, display_name=n)
            sub["file"].pop("path", None)
            inner.append(sub)
            for ind in sub["indicators"]:
                if ind["severity"] in ("medium", "high", "critical"):
                    inds.append(Indicator(f"inner_{ind['id']}", ind["severity"], f"В архиве ({os.path.basename(n)}): {ind['title']}",
                                          ind["evidence"][:3], "архив"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return info, inds, inner


class _SafetyCfg:
    junk_extensions = []
    junk_keywords = []
    skip_junk = False
    warn_dangerous = True


# ------------------------------------- строки -------------------------------------

def _strings_and_iocs(path, kind, size):
    with open(path, "rb") as f:
        data = f.read(MAX_STRINGS_SCAN)
    if kind in ("script", "text"):
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            text = data.decode("utf-16", "replace")
        else:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = data.decode("cp1251", "replace")
    else:
        ascii_s = re.findall(rb"[\x20-\x7e]{6,}", data)
        wide_s = re.findall(rb"(?:[\x20-\x7e]\x00){6,}", data)
        text = "\n".join([s.decode("ascii") for s in ascii_s] + [s.decode("utf-16-le") for s in wide_s])
    inds = []
    urls = sorted(set(re.findall(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,200}", text)))
    noise = ("schemas.microsoft.com", "www.w3.org", "schemas.openxmlformats.org", "ocsp.", "crl.", "digicert",
             "verisign", "symantec.com", "sectigo", "globalsign", "usertrust", "thawte", "comodoca", "microsoft.com/pki",
             "ns.adobe.com", "purl.org", "apache.org/licenses", "xml.org")
    interesting_urls = [u for u in urls if not any(n in u.lower() for n in noise)]
    ips = []
    for ip in sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_global and not ip.endswith(".0") and ip.count("0.") < 2:
            ips.append(ip)
    commands = []
    for cid, sev, title, rx in COMMAND_PATTERNS:
        found = sorted(set(m.group(0)[:120] for m in re.finditer(rx, text, re.IGNORECASE)))
        if found:
            # В обычных программах эти слова встречаются в справке и настройках; в сценариях — это сами команды
            if kind not in ("script", "lnk") and sev == "medium":
                sev = "low"
            inds.append(Indicator(f"cmd_{cid}", sev, title, found[:5], "команды в файле"))
            commands.append({"title": title, "matches": found[:10]})
    if kind in ("script", "lnk", "text"):
        b64 = re.findall(r"[A-Za-z0-9+/]{200,}={0,2}", text)
        if b64:
            inds.append(Indicator("script_base64", "medium", "Длинные закодированные фрагменты (скрытый код)",
                                  [f"фрагментов: {len(b64)}, самый длинный — {max(map(len, b64))} символов"], "сценарий"))
        chars = len(re.findall(r"\[char\]\s*\d+|chr\s*\(\s*\d+|String\.fromCharCode", text, re.IGNORECASE))
        if chars > 20:
            inds.append(Indicator("script_charcodes", "medium", "Код собран из кодов символов (запутывание)",
                                  [f"вставок кодов символов: {chars}"], "сценарий"))
    if kind == "lnk" and re.search(r"powershell|cmd(\.exe)?\s*/c|mshta|wscript|rundll32", text, re.IGNORECASE):
        inds.append(Indicator("lnk_command", "high", "Ярлык запускает команды вместо обычного файла",
                              re.findall(r"(?:powershell|cmd|mshta|wscript|rundll32)[^\n]{0,100}", text, re.IGNORECASE)[:3],
                              "ярлык"))
    if ips and kind in ("pe", "script", "lnk"):
        inds.append(Indicator("ioc_ip", "low", "В файле зашиты IP-адреса в интернете", ips[:10], "сеть"))
    return {"urls": interesting_urls[:100], "ips": ips[:100], "commands": commands}, inds


# ------------------------------------- YARA -------------------------------------

def _rules_paths():
    paths = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.yar")]
    user = os.path.join(os.environ.get("APPDATA", ""), "VeTTor", "yara")
    if os.path.isdir(user):
        paths += [os.path.join(user, f) for f in sorted(os.listdir(user)) if f.lower().endswith((".yar", ".yara"))]
    return paths


def _yara(path, size):
    try:
        import yara
    except ImportError:
        return [], [], "недоступно (модуль YARA не установлен)"
    if size > MAX_YARA:
        return [], [], "пропущено: файл больше 256 МБ"
    sources = {}
    errors = []
    for i, p in enumerate(_rules_paths()):
        try:
            yara.compile(filepath=p)
            sources[f"ns{i}"] = p
        except yara.Error as e:
            errors.append(f"{os.path.basename(p)}: {e}")
    if not sources:
        return [], [], "ошибка: правила не загрузились"
    rules = yara.compile(filepaths=sources)
    try:
        matches = rules.match(path, timeout=60)
    except yara.TimeoutError:
        return [], [], "прервано: превышено время"
    except yara.Error as e:
        return [], [], f"ошибка: {e}"
    out, inds = [], []
    for m in matches:
        sev = m.meta.get("severity", "medium")
        title = m.meta.get("title", m.rule)
        out.append({"rule": m.rule, "title": title, "severity": sev})
        inds.append(Indicator(f"yara_{m.rule}", sev, title, [f"сработало правило YARA {m.rule}"] +
                              ([m.meta["description"]] if m.meta.get("description") else []), "сигнатуры"))
    state = "выполнено" + (f" (не загрузились свои правила: {'; '.join(errors)})" if errors else "")
    return out, inds, state
