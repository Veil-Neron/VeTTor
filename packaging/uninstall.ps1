﻿# Удаляет VeTTor. Настройки и список торрентов в %APPDATA%\VeTTor и скачанные файлы не трогаются.
$dst = Join-Path $env:LOCALAPPDATA "Programs\VeTTor"
$title = "VeTTor"

Get-Process VeTTor -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

foreach ($dir in @([Environment]::GetFolderPath("Desktop"), [Environment]::GetFolderPath("Programs"))) {
    Remove-Item (Join-Path $dir "$title.lnk") -ErrorAction SilentlyContinue
}

# Связь с Windows (если включали в настройках) — удаляем только свои записи
$classes = "HKCU:\Software\Classes"
Remove-Item "$classes\VeTTor.torrent", "$classes\VeTTor.magnet", "HKCU:\Software\VeTTor" -Recurse -ErrorAction SilentlyContinue
if ((Get-ItemProperty "$classes\.torrent" -ErrorAction SilentlyContinue).'(default)' -eq "VeTTor.torrent") {
    Set-ItemProperty "$classes\.torrent" -Name "(default)" -Value ""
}
Remove-ItemProperty "$classes\.torrent\OpenWithProgids" -Name "VeTTor.torrent" -ErrorAction SilentlyContinue
$magnetCmd = (Get-ItemProperty "$classes\magnet\shell\open\command" -ErrorAction SilentlyContinue).'(default)'
if ($magnetCmd -like "*VeTTor*") { Remove-Item "$classes\magnet" -Recurse -ErrorAction SilentlyContinue }
Remove-ItemProperty "HKCU:\Software\RegisteredApplications" -Name "VeTTor" -ErrorAction SilentlyContinue
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "VeTTor" -ErrorAction SilentlyContinue
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\VeTTor" -Recurse -ErrorAction SilentlyContinue

# Скрипт лежит внутри удаляемой папки — удаляем её отдельным процессом после выхода
Start-Process cmd.exe -ArgumentList "/c timeout /t 2 >nul & rd /s /q `"$dst`"" -WindowStyle Hidden
