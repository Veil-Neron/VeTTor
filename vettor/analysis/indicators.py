"""Признаки (индикаторы) и итоговая оценка риска.

Правила оценки сознательно осторожные: один неоднозначный признак (нет подписи, упаковщик,
подозрительная функция) не делает файл вредоносным — важны сочетания и надёжные сигналы
(антивирус, сигнатура известной угрозы)."""
from dataclasses import asdict, dataclass, field

WEIGHTS = {"info": 0, "low": 1, "medium": 3, "high": 8, "critical": 100}
ORDER = ["critical", "high", "medium", "low", "info"]

VERDICTS = {
    "malicious": ("Вредоносный", "имеются убедительные доказательства угрозы"),
    "high": ("Высокий риск", "обнаружено несколько серьёзных подозрительных признаков"),
    "review": ("Требует проверки", "результаты неоднозначны"),
    "low": ("Низкий риск", "применённые методы не выявили значимых угроз"),
    "insufficient": ("Недостаточно данных", "анализ не завершён или его результаты неполны"),
}

RECOMMENDATIONS = {
    "malicious": "Не запускайте и не открывайте файл. Удалите его и проверьте компьютер антивирусом. "
                 "Если файл уже запускался — смените пароли с другого устройства.",
    "high": "Не запускайте файл, если не уверены в источнике. Дождитесь проверки поведения в песочнице "
            "(следующий этап) или проверьте файл на VirusTotal.",
    "review": "Запускайте только если доверяете источнику. Посмотрите, на чём основаны признаки ниже: "
              "многие из них встречаются и у обычных программ.",
    "low": "Явных угроз не найдено. Это не гарантия: файл не запускался, и его поведение не проверялось.",
    "insufficient": "Проверка не дала полной картины — не считайте файл безопасным. Повторите проверку "
                    "или проверьте файл другим способом.",
}


@dataclass
class Indicator:
    id: str
    severity: str  # info | low | medium | high | critical
    title: str
    evidence: list = field(default_factory=list)  # наблюдаемые факты
    category: str = ""
    weight: int = None  # явный вес (например, отрицательный у действительной подписи)

    def score(self):
        return WEIGHTS[self.severity] if self.weight is None else self.weight

    def to_dict(self):
        d = asdict(self)
        d["weight"] = self.score()
        d["evidence"] = [e for e in d["evidence"] if e]
        return d


def decide(report):
    inds = report.get("indicators", [])
    score = max(0, sum(i["weight"] for i in inds))
    counts = {s: sum(1 for i in inds if i["severity"] == s) for s in ORDER}
    checks = report.get("checks", {})
    done = [k for k, v in checks.items() if v.startswith("выполнено")]
    failed = [k for k, v in checks.items() if v.startswith(("ошибка", "прервано"))]

    if report.get("error"):
        verdict = "insufficient"
    elif counts["critical"]:
        verdict = "malicious"
    elif counts["high"] >= 2 or score >= 16:
        verdict = "high"
    elif counts["high"] == 1 or score >= 6:
        verdict = "review"
    elif len(done) < 5 or "Разбор содержимого" in failed:
        verdict = "insufficient"
    else:
        verdict = "low"

    # Уверенность: насколько полно выполнены проверки и насколько надёжны сигналы
    defender_ok = checks.get("Microsoft Defender", "").startswith("выполнено")
    if verdict == "malicious":
        confidence = "высокая"
    elif verdict == "insufficient":
        confidence = "низкая"
    elif len(failed) == 0 and defender_ok and len(done) >= 7:
        confidence = "средняя"
    else:
        confidence = "низкая"

    top = sorted((i for i in inds if i["severity"] in ("critical", "high", "medium")),
                 key=lambda i: ORDER.index(i["severity"]))
    if top:
        reasons = [i["title"] for i in top[:4]]
        summary = "Основание: " + "; ".join(reasons) + "."
    elif verdict == "low":
        summary = "Серьёзных признаков угрозы не найдено."
    else:
        summary = "Проверка не завершена: " + (report.get("error") or ", ".join(failed) or "выполнено мало проверок") + "."
    title, meaning = VERDICTS[verdict]
    return {"code": verdict, "title": title, "meaning": meaning, "confidence": confidence, "score": score,
            "summary": summary, "recommendation": RECOMMENDATIONS[verdict],
            "note": "Уверенность ограничена: файл не запускался (динамический анализ — следующий этап)."
            if verdict != "malicious" else ""}
