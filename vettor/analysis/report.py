"""История проверок и экспорт отчёта (HTML, JSON)."""
import html
import json
import os

from ..config import DATA_DIR
from ..util import fmt_size

HISTORY_DIR = os.path.join(DATA_DIR, "analysis")
COLORS = {"malicious": "#dc2626", "high": "#ea580c", "review": "#ca8a04", "low": "#16a34a", "insufficient": "#6b7280"}
SEV_NAMES = {"critical": "критическая", "high": "высокая", "medium": "средняя", "low": "низкая", "info": "к сведению"}


def save(report):
    os.makedirs(HISTORY_DIR, exist_ok=True)
    stamp = report.get("started", "").replace(":", "-").replace("T", "_")
    name = f"{stamp}_{report['file'].get('sha256', 'nohash')[:12]}.json"
    path = os.path.join(HISTORY_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)
    return path


def history():
    if not os.path.isdir(HISTORY_DIR):
        return []
    out = []
    for name in sorted(os.listdir(HISTORY_DIR), reverse=True):
        if name.endswith(".json"):
            p = os.path.join(HISTORY_DIR, name)
            try:
                with open(p, encoding="utf-8") as f:
                    out.append((p, json.load(f)))
            except (OSError, ValueError):
                continue
    return out


def delete(path):
    if os.path.dirname(os.path.abspath(path)) == os.path.abspath(HISTORY_DIR):
        os.remove(path)


def export_json(report, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def _e(x):
    return html.escape(str(x))


def export_html(report, path):
    v = report["verdict"]
    f = report["file"]
    color = COLORS.get(v["code"], "#6b7280")
    rows = []

    def section(title, body):
        rows.append(f"<h2>{_e(title)}</h2>{body}")

    def table(head, data):
        th = "".join(f"<th>{_e(h)}</th>" for h in head)
        tr = "".join("<tr>" + "".join(f"<td>{_e(c)}</td>" for c in r) + "</tr>" for r in data)
        return f"<table><tr>{th}</tr>{tr}</table>"

    section("О файле", table(["Поле", "Значение"], [
        ["Имя", f.get("name", "")], ["Тип", f.get("type_name", "")],
        ["Размер", f"{fmt_size(f.get('size', 0))} ({f.get('size', 0)} байт)"],
        ["SHA-256", f.get("sha256", "")], ["SHA-1", f.get("sha1", "")], ["MD5", f.get("md5", "")],
        ["Проверка начата", report.get("started", "")], ["Длительность", f"{report.get('duration_sec', '—')} с"],
    ]))
    inds = report.get("indicators", [])
    section("Обнаруженные признаки (факты, на которых основан вывод)",
            table(["Важность", "Признак", "Наблюдения"],
                  [[SEV_NAMES.get(i["severity"], i["severity"]), i["title"], "; ".join(i["evidence"])] for i in inds])
            if inds else "<p>Признаков не обнаружено.</p>")
    sig = report.get("signature")
    if sig:
        section("Цифровая подпись", table(["Поле", "Значение"], [[k, v2] for k, v2 in sig.items() if v2]))
    pe = report.get("pe")
    if pe:
        section("Программа Windows", table(["Поле", "Значение"], [
            ["Вид", f"{pe.get('kind')} ({pe.get('machine')}, {pe.get('subsystem')})"],
            [".NET", "да" if pe.get("dotnet") else "нет"], ["Дата сборки", pe.get("compiled", "")],
            ["Импортировано функций", pe.get("imports_count", 0)],
            ["Библиотеки", ", ".join(pe.get("import_dlls", []))],
        ] + [[k, ", ".join(x)] for k, x in pe.get("suspicious_imports", {}).items()]
           + [[k, x] for k, x in pe.get("version", {}).items()]))
        section("Секции", table(["Имя", "Размер", "Энтропия", "Исполняемая", "Записываемая"],
                                [[s["name"], s["raw_size"], s["entropy"], "да" if s["exec"] else "",
                                  "да" if s["write"] else ""] for s in pe.get("sections", [])]))
    st = report.get("strings") or {}
    if st.get("urls") or st.get("ips") or st.get("commands"):
        body = ""
        if st.get("urls"):
            body += "<h3>Адреса в интернете</h3><ul>" + "".join(f"<li><code>{_e(u)}</code></li>" for u in st["urls"]) + "</ul>"
        if st.get("ips"):
            body += "<h3>IP-адреса</h3><p><code>" + _e(", ".join(st["ips"])) + "</code></p>"
        for c in st.get("commands", []):
            body += f"<h3>{_e(c['title'])}</h3><ul>" + "".join(f"<li><code>{_e(m)}</code></li>" for m in c["matches"]) + "</ul>"
        section("Сетевые индикаторы и команды (найдены в файле, не выполнялись)", body)
    arc = report.get("archive")
    if arc:
        section(f"Содержимое архива ({arc.get('count', 0)} файлов, {fmt_size(arc.get('total_unpacked', 0))})",
                table(["Файл", "Размер"], [[e["name"], fmt_size(e["size"])] for e in arc.get("entries", [])]))
    for sub in report.get("inner", []):
        sv = sub.get("verdict", {})
        section(f"Файл в архиве: {sub['file'].get('name')}",
                f"<p>{_e(sv.get('title', sub.get('skipped', '')))} — {_e(sv.get('summary', ''))}</p>")
    section("Выполненные проверки", table(["Проверка", "Результат"], list(report.get("checks", {}).items())))
    section("Ограничения анализа", "<ul>" + "".join(f"<li>{_e(x)}</li>" for x in report.get("limitations", [])) + "</ul>")

    doc = f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Отчёт о проверке: {_e(f.get('name', ''))}</title>
<style>
body{{font-family:Segoe UI,system-ui,sans-serif;max-width:980px;margin:24px auto;padding:0 16px;color:#1f2328;background:#fff}}
h1{{font-size:22px}} h2{{font-size:17px;margin-top:28px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}}
h3{{font-size:14px}} table{{border-collapse:collapse;width:100%;font-size:13px}}
td,th{{border:1px solid #e5e7eb;padding:6px 8px;text-align:left;vertical-align:top;word-break:break-word}}
th{{background:#f6f7f9}} code{{font-size:12px;word-break:break-all}}
.verdict{{border-left:6px solid {color};background:#f9fafb;padding:12px 16px;border-radius:6px}}
.verdict b{{color:{color};font-size:20px}} .muted{{color:#6b7280;font-size:13px}}
</style></head><body>
<h1>Отчёт о проверке файла «{_e(f.get('name', ''))}»</h1>
<div class="verdict"><b>{_e(v['title'])}</b> — {_e(v['meaning'])}<br>
Уверенность: {_e(v['confidence'])}<br>{_e(v['summary'])}<br><br><b style="font-size:14px;color:#1f2328">Рекомендация:</b> {_e(v['recommendation'])}
<p class="muted">{_e(v.get('note', ''))}</p></div>
{''.join(rows)}
<p class="muted">Отчёт создан программой VeTTor. Статический анализ: файл не запускался и никуда не отправлялся.</p>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f2:
        f2.write(doc)
