/*
  Встроенные правила VeTTor. meta.severity: info | low | medium | high | critical,
  meta.title — что показать пользователю. Свои правила кладите в %APPDATA%\VeTTor\yara\*.yar
*/

rule EICAR_Test_File
{
    meta:
        severity = "critical"
        title = "Тестовая сигнатура антивирусов EICAR"
        description = "Безвредный файл, который все антивирусы по договорённости считают вирусом"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar at 0x2B or $eicar in (0..256)
}

rule Mimikatz_Strings
{
    meta:
        severity = "critical"
        title = "Строки утилиты кражи паролей Mimikatz"
        description = "Mimikatz извлекает пароли и ключи из памяти Windows"
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide nocase
        $b = "lsadump::sam" ascii wide nocase
        $c = "gentilkiwi" ascii wide
        $d = "mimikatz" ascii wide nocase
        $e = "kerberos::golden" ascii wide nocase
    condition:
        2 of them
}

rule CobaltStrike_Beacon_Strings
{
    meta:
        severity = "critical"
        title = "Признаки Cobalt Strike Beacon (инструмент удалённого управления, популярный у злоумышленников)"
    strings:
        $a = "%s as %s\\%s: %d" ascii
        $b = "beacon.dll" ascii
        $c = "beacon.x64.dll" ascii
        $d = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $e = "ReflectiveLoader" ascii
    condition:
        3 of them
}

rule Ransom_Note_Text
{
    meta:
        severity = "high"
        title = "Текст требования выкупа (типично для шифровальщиков)"
    strings:
        $a = "your files have been encrypted" ascii wide nocase
        $b = "all your files are encrypted" ascii wide nocase
        $c = "to decrypt your files" ascii wide nocase
        $d = "ваши файлы зашифрованы" wide nocase
        $e = "bitcoin" ascii wide nocase
        $f = ".onion" ascii wide nocase
        $g = "private key" ascii wide nocase
    condition:
        1 of ($a, $b, $c, $d) and 1 of ($e, $f, $g)
}

rule Browser_Credential_Theft
{
    meta:
        severity = "high"
        title = "Обращение к сохранённым паролям браузеров и кошелькам (типично для «стилеров»)"
    strings:
        $a = "\\Google\\Chrome\\User Data" ascii wide nocase
        $b = "Login Data" ascii wide
        $c = "logins.json" ascii wide
        $d = "key4.db" ascii wide
        $e = "wallet.dat" ascii wide nocase
        $f = "\\Telegram Desktop\\tdata" ascii wide nocase
        $g = "\\Exodus\\exodus.wallet" ascii wide nocase
        $h = "\\Yandex\\YandexBrowser\\User Data" ascii wide nocase
        $i = "\\Opera Software\\Opera Stable" ascii wide nocase
        $j = "Local State" ascii wide
    condition:
        4 of them
}

rule Shadow_Copy_Deletion
{
    meta:
        severity = "high"
        title = "Команды удаления резервных копий Windows (типично для шифровальщиков)"
    strings:
        $a = "vssadmin delete shadows" ascii wide nocase
        $b = "shadowcopy delete" ascii wide nocase
        $c = "wbadmin delete catalog" ascii wide nocase
        $d = "recoveryenabled no" ascii wide nocase
    condition:
        any of them
}

rule UPX_Packed
{
    meta:
        severity = "low"
        title = "Сжат упаковщиком UPX"
        description = "UPX используют и обычные программы, и вирусы — сам по себе это не признак заражения"
    strings:
        $a = "UPX0" ascii
        $b = "UPX1" ascii
        $c = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule AutoIt_Compiled
{
    meta:
        severity = "info"
        title = "Скомпилированный сценарий AutoIt"
        description = "AutoIt часто используют для простых вирусов, но и для обычных утилит"
    strings:
        $a = "AU3!EA06" ascii
        $b = ">>>AUTOIT SCRIPT<<<" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Encoded_PowerShell_Launch
{
    meta:
        severity = "medium"
        title = "Запуск PowerShell со скрытой (закодированной) командой"
    strings:
        $a = /powershell(\.exe)?["']?\s+[^\r\n]{0,80}-(e|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+\/=]{40,}/ nocase ascii wide
    condition:
        $a
}
