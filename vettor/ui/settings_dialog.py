import os
import random

from PySide6.QtCore import QTime
from PySide6.QtNetwork import QNetworkInterface
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QDoubleSpinBox, QFileDialog, QFormLayout,
    QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QPushButton, QScrollArea, QSpinBox,
    QStackedWidget, QTimeEdit, QVBoxLayout, QWidget,
)

from .. import extract, winintegration
from .icons import icon


def _spin(value, maximum=10 ** 7, suffix=""):
    s = QSpinBox()
    s.setRange(0, maximum)
    s.setValue(int(value))
    if suffix:
        s.setSuffix(suffix)
    return s


def _hint(text):
    lbl = QLabel(text)
    lbl.setObjectName("Muted")
    lbl.setWordWrap(True)
    return lbl


def _path_row(edit, title, file_mode=False):
    row = QHBoxLayout()
    row.addWidget(edit, 1)
    b = QPushButton(icon("folder"), "")

    def pick():
        if file_mode:
            path, _ = QFileDialog.getOpenFileName(None, title, edit.text(), "IP-фильтры (*.dat *.p2p *.txt);;Все файлы (*)")
        else:
            path = QFileDialog.getExistingDirectory(None, title, edit.text())
        if path:
            edit.setText(os.path.normpath(path))
    b.clicked.connect(pick)
    row.addWidget(b)
    return row


class SettingsDialog(QDialog):
    def __init__(self, cfg, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.setWindowTitle("Настройки")
        self.resize(820, 600)
        outer = QVBoxLayout(self)
        body = QHBoxLayout()
        outer.addLayout(body, 1)
        self.nav = QListWidget()
        self.nav.setObjectName("SettingsNav")
        self.nav.setFixedWidth(190)
        self.pages = QStackedWidget()
        body.addWidget(self.nav)
        body.addWidget(self.pages, 1)
        for title, builder in [
            ("Основные", self._general), ("Скорость", self._speed), ("Подключение", self._connection),
            ("Безопасность", self._privacy), ("Защита от вирусов", self._junk), ("Экономия места", self._space), ("Раздача", self._seeding),
        ]:
            self.nav.addItem(title)
            page = QWidget()
            lay = QVBoxLayout(page)
            builder(lay)
            lay.addStretch(1)
            scroll = QScrollArea()
            scroll.setWidget(page)
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QScrollArea.NoFrame)
            self.pages.addWidget(scroll)
        self.nav.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.nav.setCurrentRow(0)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        ok = buttons.button(QDialogButtonBox.Ok)
        ok.setText("Сохранить")
        ok.setProperty("primary", True)
        buttons.button(QDialogButtonBox.Cancel).setText("Отмена")
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        outer.addWidget(buttons)

    def open_page(self, title):
        for i in range(self.nav.count()):
            if self.nav.item(i).text() == title:
                self.nav.setCurrentRow(i)

    # ---------- страницы ----------
    def _general(self, lay):
        c = self.cfg
        form = QFormLayout()
        self.download_dir = QLineEdit(c.download_dir)
        form.addRow("Папка загрузок:", _path_row(self.download_dir, "Папка загрузок"))
        self.theme = QComboBox()
        for code, name in (("system", "Как в системе"), ("dark", "Тёмная"), ("light", "Светлая")):
            self.theme.addItem(name, code)
        self.theme.setCurrentIndex(max(0, self.theme.findData(c.theme)))
        form.addRow("Тема:", self.theme)
        lay.addLayout(form)
        self.ask_on_add = QCheckBox("Спрашивать, какие файлы скачивать (иначе загрузка начинается сразу)")
        self.start_paused = QCheckBox("Добавлять торренты на паузе")
        self.confirm_remove = QCheckBox("Спрашивать подтверждение при удалении")
        self.notify = QCheckBox("Уведомлять о завершении загрузки")
        self.min_tray = QCheckBox("Сворачивать в область уведомлений")
        self.close_tray = QCheckBox("При закрытии окна оставаться в области уведомлений")
        self.autostart = QCheckBox("Запускать вместе с Windows (свёрнутым)")
        for w, v in ((self.ask_on_add, c.ask_on_add), (self.start_paused, c.start_paused),
                     (self.confirm_remove, c.confirm_remove), (self.notify, c.notify_complete),
                     (self.min_tray, c.minimize_to_tray), (self.close_tray, c.close_to_tray),
                     (self.autostart, c.start_with_windows)):
            w.setChecked(v)
            lay.addWidget(w)
        box = QGroupBox("Связь с Windows")
        bl = QVBoxLayout(box)
        self.assoc = QCheckBox("Открывать .torrent-файлы и magnet-ссылки в VeTTor")
        self.assoc.setChecked(c.register_associations)
        bl.addWidget(self.assoc)
        bl.addWidget(_hint("Если раньше ссылки открывал другой клиент (например, MediaGet), Windows может "
                           "продолжать использовать его. Тогда выберите VeTTor в окне «Приложения по умолчанию»."))
        b = QPushButton("Открыть «Приложения по умолчанию»")
        b.clicked.connect(winintegration.open_default_apps)
        row = QHBoxLayout()
        row.addWidget(b)
        row.addStretch(1)
        bl.addLayout(row)
        lay.addWidget(box)

    def _speed(self, lay):
        c = self.cfg
        box = QGroupBox("Обычные ограничения")
        f = QFormLayout(box)
        self.dl = _spin(c.dl_limit_kib, suffix=" КБ/с")
        self.ul = _spin(c.ul_limit_kib, suffix=" КБ/с")
        f.addRow("Загрузка:", self.dl)
        f.addRow("Отдача:", self.ul)
        f.addRow(_hint("0 — без ограничений."))
        lay.addWidget(box)
        box = QGroupBox("Альтернативные ограничения (значок спидометра внизу окна)")
        f = QFormLayout(box)
        self.alt_dl = _spin(c.alt_dl_limit_kib, suffix=" КБ/с")
        self.alt_ul = _spin(c.alt_ul_limit_kib, suffix=" КБ/с")
        f.addRow("Загрузка:", self.alt_dl)
        f.addRow("Отдача:", self.alt_ul)
        self.schedule = QCheckBox("Включать по расписанию")
        self.schedule.setChecked(c.schedule_enabled)
        f.addRow(self.schedule)
        row = QHBoxLayout()
        self.sched_from = QTimeEdit(QTime.fromString(c.schedule_from, "HH:mm"))
        self.sched_to = QTimeEdit(QTime.fromString(c.schedule_to, "HH:mm"))
        for w in (self.sched_from, self.sched_to):
            w.setDisplayFormat("HH:mm")
        row.addWidget(QLabel("с"))
        row.addWidget(self.sched_from)
        row.addWidget(QLabel("до"))
        row.addWidget(self.sched_to)
        row.addStretch(1)
        f.addRow(row)
        f.addRow(_hint("Например, днём, чтобы торренты не мешали работе или играм."))
        lay.addWidget(box)

    def _connection(self, lay):
        c = self.cfg
        form = QFormLayout()
        row = QHBoxLayout()
        self.port = QSpinBox()
        self.port.setRange(1024, 65535)
        self.port.setValue(int(c.listen_port))
        rnd = QPushButton("Случайный")
        rnd.clicked.connect(lambda: self.port.setValue(random.randint(20000, 60000)))
        row.addWidget(self.port)
        row.addWidget(rnd)
        row.addStretch(1)
        form.addRow("Порт входящих соединений:", row)
        self.max_conn = _spin(c.max_connections, 5000)
        self.max_dl = _spin(c.max_active_downloads, 100)
        self.max_seed = _spin(c.max_active_seeds, 100)
        form.addRow("Максимум соединений:", self.max_conn)
        form.addRow("Одновременных загрузок:", self.max_dl)
        form.addRow("Одновременных раздач:", self.max_seed)
        lay.addLayout(form)
        self.upnp = QCheckBox("Пробрасывать порт через роутер (UPnP)")
        self.natpmp = QCheckBox("Пробрасывать порт через NAT-PMP")
        self.upnp.setChecked(c.enable_upnp)
        self.natpmp.setChecked(c.enable_natpmp)
        lay.addWidget(self.upnp)
        lay.addWidget(self.natpmp)

    def _privacy(self, lay):
        c = self.cfg
        form = QFormLayout()
        self.encryption = QComboBox()
        self.encryption.addItems(["Предпочитать шифрование", "Только шифрованные соединения", "Не шифровать"])
        self.encryption.setCurrentIndex(int(c.encryption))
        form.addRow("Шифрование:", self.encryption)
        lay.addLayout(form)
        lay.addWidget(_hint("Шифрование мешает провайдеру распознавать и замедлять торрент-трафик. "
                            "Режим «только шифрованные» безопаснее, но пиров будет меньше."))
        self.anonymous = QCheckBox("Анонимный режим (не сообщать пирам версию клиента и системы)")
        self.dht = QCheckBox("DHT — поиск пиров без трекера")
        self.lsd = QCheckBox("Поиск пиров в локальной сети")
        self.pex = QCheckBox("Обмен пирами (PeX)")
        for w, v in ((self.anonymous, c.anonymous_mode), (self.dht, c.enable_dht),
                     (self.lsd, c.enable_lsd), (self.pex, c.enable_pex)):
            w.setChecked(v)
            lay.addWidget(w)
        lay.addWidget(_hint("Для закрытых трекеров DHT, PeX и локальный поиск обычно отключают."))

        box = QGroupBox("Привязка к сетевому интерфейсу (VPN)")
        bl = QVBoxLayout(box)
        self.iface = QComboBox()
        self.iface.addItem("Любой интерфейс", "")
        for iface in QNetworkInterface.allInterfaces():
            if iface.flags() & QNetworkInterface.InterfaceFlag.IsLoopBack:
                continue
            self.iface.addItem(iface.humanReadableName(), iface.name())
        idx = self.iface.findData(c.bind_interface)
        if idx < 0 and c.bind_interface:
            self.iface.addItem(f"{c.bind_interface} (сейчас отключён)", c.bind_interface)
            idx = self.iface.count() - 1
        self.iface.setCurrentIndex(max(0, idx))
        bl.addWidget(self.iface)
        bl.addWidget(_hint("Если выбрать интерфейс VPN, трафик пойдёт только через него. "
                           "Когда VPN отключится, загрузки автоматически остановятся и продолжатся после переподключения."))
        lay.addWidget(box)

        box = QGroupBox("Прокси")
        f = QFormLayout(box)
        self.proxy_type = QComboBox()
        for code, name in (("none", "Не использовать"), ("socks5", "SOCKS5"), ("http", "HTTP")):
            self.proxy_type.addItem(name, code)
        self.proxy_type.setCurrentIndex(max(0, self.proxy_type.findData(c.proxy_type)))
        self.proxy_host = QLineEdit(c.proxy_host)
        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(1, 65535)
        self.proxy_port.setValue(int(c.proxy_port or 1080))
        self.proxy_user = QLineEdit(c.proxy_user)
        self.proxy_pass = QLineEdit(c.proxy_password)
        self.proxy_pass.setEchoMode(QLineEdit.Password)
        self.proxy_peers = QCheckBox("Пускать через прокси и соединения с пирами")
        self.proxy_peers.setChecked(c.proxy_peers)
        f.addRow("Тип:", self.proxy_type)
        f.addRow("Адрес:", self.proxy_host)
        f.addRow("Порт:", self.proxy_port)
        f.addRow("Логин:", self.proxy_user)
        f.addRow("Пароль:", self.proxy_pass)
        f.addRow(self.proxy_peers)
        lay.addWidget(box)

        box = QGroupBox("IP-фильтр")
        bl = QVBoxLayout(box)
        self.ip_filter = QLineEdit(c.ip_filter_path)
        self.ip_filter.setPlaceholderText("Файл в формате eMule (.dat) или PeerGuardian (.p2p)")
        bl.addLayout(_path_row(self.ip_filter, "Файл IP-фильтра", file_mode=True))
        bl.addWidget(_hint("Блокирует соединения с адресами из списка."))
        lay.addWidget(box)

    def _junk(self, lay):
        c = self.cfg
        self.skip_junk = QCheckBox("Не загружать лишние файлы (ярлыки, ссылки на сайты, рекламу)")
        self.skip_junk.setChecked(c.skip_junk)
        lay.addWidget(self.skip_junk)
        self.warn_danger = QCheckBox("Предупреждать и не загружать исполняемые файлы в раздачах фильмов и музыки")
        self.warn_danger.setChecked(c.warn_dangerous)
        lay.addWidget(self.warn_danger)
        lay.addWidget(_hint("Например, «фильм.mp4.exe» или setup.exe в раздаче сериала — почти всегда вирус. "
                            "Файлы, маскирующиеся под другой тип, помечаются всегда."))
        self.motw = QCheckBox("Помечать скачанные файлы как полученные из интернета")
        self.motw.setChecked(c.mark_of_the_web)
        lay.addWidget(self.motw)
        lay.addWidget(_hint("Как в браузерах: перед запуском скачанной программы Windows SmartScreen проверит её, "
                            "а Word и Excel откроют документы в защищённом режиме."))
        self.guard = QCheckBox("Проверять каждый файл сразу после загрузки и удалять заражённые")
        self.guard.setChecked(c.guard_enabled)
        lay.addWidget(self.guard)
        lay.addWidget(_hint("Докачанный файл проверяется встроенным Microsoft Defender, а видео, музыка и картинки — "
                            "ещё и на спрятанную внутри программу. Заражённый файл удаляется и больше не загружается, "
                            "остальные файлы раздачи не затрагиваются. Любую раздачу можно проверить вручную: "
                            "правый щелчок → «Проверить антивирусом»."))
        form = QFormLayout()
        self.junk_ext = QLineEdit(" ".join(c.junk_extensions))
        self.junk_words = QLineEdit(", ".join(c.junk_keywords))
        form.addRow("Лишние расширения:", self.junk_ext)
        form.addRow("Слова в именах:", self.junk_words)
        lay.addLayout(form)
        lay.addWidget(_hint("Слова проверяются только в небольших .txt, .nfo и картинках — обычно это реклама раздающего. "
                            "В окне добавления такие файлы показаны серым, их всегда можно отметить вручную."))

    def _space(self, lay):
        c = self.cfg
        form = QFormLayout()
        self.extract_mode = QComboBox()
        for code, name in (("always", "Всегда"), ("needed", "Только если не хватает места"), ("never", "Никогда")):
            self.extract_mode.addItem(name, code)
        self.extract_mode.setCurrentIndex(max(0, self.extract_mode.findData(c.extract_mode)))
        form.addRow("Распаковывать архивы после загрузки:", self.extract_mode)
        lay.addLayout(form)
        lay.addWidget(_hint(
            "Если в раздаче архив (ZIP, RAR, TAR), VeTTor распакует его рядом и удалит архив прямо по ходу "
            "распаковки. Тогда на диске одновременно лежит не «архив + распакованное», а примерно столько, сколько "
            "занимает распакованное: игре на 50 ГБ хватит около 50–55 ГБ свободного места вместо 100. "
            "После распаковки торрент исчезает из списка и больше не раздаётся, распакованные файлы остаются."))
        lay.addWidget(_hint(
            "Ограничения: одиночный RAR удаляется только после распаковки (многотомный .part1.rar… — по ходу); "
            "для RAR нужен установленный WinRAR; архивы 7z и установщики-репаки (setup.exe + .bin) "
            "так распаковать нельзя."))
        winrar = extract.unrar_path()
        lay.addWidget(_hint(("✔ WinRAR найден: " + winrar) if winrar else "⚠ WinRAR не найден — RAR-архивы распаковываться не будут."))
        self.compress_extracted = QCheckBox("Сжимать распакованные файлы средствами Windows (экономит 20–50% у игр и программ)")
        self.compress_extracted.setChecked(c.compress_extracted)
        lay.addWidget(self.compress_extracted)
        lay.addWidget(_hint("Сжатие прозрачное: файлы остаются обычными и открываются как раньше. "
                            "Любую папку можно сжать и вручную — кнопкой «Сжатие» на панели инструментов."))

    def _seeding(self, lay):
        c = self.cfg
        form = QFormLayout()
        self.ratio = QDoubleSpinBox()
        self.ratio.setRange(0, 100)
        self.ratio.setSingleStep(0.5)
        self.ratio.setValue(float(c.ratio_limit))
        self.seed_time = _spin(c.seed_time_limit_min, 100000, " мин")
        form.addRow("Остановить при рейтинге:", self.ratio)
        form.addRow("Остановить через:", self.seed_time)
        lay.addLayout(form)
        lay.addWidget(_hint("0 — без ограничения. Раздача — это отдача уже скачанного другим людям; "
                            "без неё торренты не работают, поэтому не отключайте её совсем."))

    # ---------- сохранение ----------
    def _save(self):
        c = self.cfg
        c.download_dir = self.download_dir.text().strip() or c.download_dir
        c.theme = self.theme.currentData()
        c.ask_on_add = self.ask_on_add.isChecked()
        c.start_paused = self.start_paused.isChecked()
        c.confirm_remove = self.confirm_remove.isChecked()
        c.notify_complete = self.notify.isChecked()
        c.minimize_to_tray = self.min_tray.isChecked()
        c.close_to_tray = self.close_tray.isChecked()
        if self.autostart.isChecked() != c.start_with_windows:
            c.start_with_windows = self.autostart.isChecked()
            winintegration.set_autostart(c.start_with_windows)
        if self.assoc.isChecked() != c.register_associations:
            c.register_associations = self.assoc.isChecked()
            winintegration.set_associations(c.register_associations)

        c.dl_limit_kib, c.ul_limit_kib = self.dl.value(), self.ul.value()
        c.alt_dl_limit_kib, c.alt_ul_limit_kib = self.alt_dl.value(), self.alt_ul.value()
        c.schedule_enabled = self.schedule.isChecked()
        c.schedule_from = self.sched_from.time().toString("HH:mm")
        c.schedule_to = self.sched_to.time().toString("HH:mm")

        c.listen_port = self.port.value()
        c.max_connections = self.max_conn.value()
        c.max_active_downloads = self.max_dl.value()
        c.max_active_seeds = self.max_seed.value()
        c.enable_upnp = self.upnp.isChecked()
        c.enable_natpmp = self.natpmp.isChecked()

        c.encryption = self.encryption.currentIndex()
        c.anonymous_mode = self.anonymous.isChecked()
        c.enable_dht = self.dht.isChecked()
        c.enable_lsd = self.lsd.isChecked()
        c.enable_pex = self.pex.isChecked()
        c.bind_interface = self.iface.currentData()
        c.proxy_type = self.proxy_type.currentData()
        c.proxy_host = self.proxy_host.text().strip()
        c.proxy_port = self.proxy_port.value()
        c.proxy_user = self.proxy_user.text().strip()
        c.proxy_password = self.proxy_pass.text()
        c.proxy_peers = self.proxy_peers.isChecked()
        c.ip_filter_path = self.ip_filter.text().strip()

        c.skip_junk = self.skip_junk.isChecked()
        c.warn_dangerous = self.warn_danger.isChecked()
        exts = [e.strip().lower() for e in self.junk_ext.text().replace(",", " ").split() if e.strip()]
        c.junk_extensions = [e if e.startswith(".") else "." + e for e in exts]
        c.junk_keywords = [w.strip() for w in self.junk_words.text().split(",") if w.strip()]

        c.ratio_limit = self.ratio.value()
        c.seed_time_limit_min = self.seed_time.value()

        c.mark_of_the_web = self.motw.isChecked()
        c.extract_mode = self.extract_mode.currentData()
        c.compress_extracted = self.compress_extracted.isChecked()
        c.guard_enabled = self.guard.isChecked()
        c.save()
        self.accept()
