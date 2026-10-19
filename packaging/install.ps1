# Устанавливает собранный VeTTor.exe для текущего пользователя (права администратора не нужны).
$ErrorActionPreference = "Stop"
$src = Join-Path $PSScriptRoot "..\dist\VeTTor"
$dst = Join-Path $env:LOCALAPPDATA "Programs\VeTTor"
$exe = Join-Path $dst "VeTTor.exe"
$title = "VeTTor"
$version = "1.3.0"

if (-not (Test-Path (Join-Path $src "VeTTor.exe"))) { throw "Сначала соберите программу: dist\VeTTor\VeTTor.exe не найден." }

$shell = New-Object -ComObject WScript.Shell
$places = @([Environment]::GetFolderPath("Desktop"), [Environment]::GetFolderPath("Programs"))

# До версии 1.3 программа называлась «Поток» (Potok) — убираем старую установку.
# Настройки и торренты из %APPDATA%\Potok VeTTor перенесёт сам при первом запуске.
Get-Process Potok, VeTTor -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500
$legacy = Join-Path $env:LOCALAPPDATA "Programs\Potok"
if (Test-Path $legacy) { Remove-Item $legacy -Recurse -Force }
foreach ($dir in $places) { Remove-Item (Join-Path $dir "Поток.lnk") -ErrorAction SilentlyContinue }
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Potok" -Recurse -ErrorAction SilentlyContinue

if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
Copy-Item $src $dst -Recurse
Copy-Item (Join-Path $PSScriptRoot "uninstall.ps1") $dst

foreach ($dir in $places) {
    $lnk = $shell.CreateShortcut((Join-Path $dir "$title.lnk"))
    $lnk.TargetPath = $exe
    $lnk.WorkingDirectory = $dst
    $lnk.IconLocation = "$exe,0"
    $lnk.Description = "Торрент-клиент без рекламы"
    $lnk.Save()
}

$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\VeTTor"
New-Item $key -Force | Out-Null
$size = [int]((Get-ChildItem $dst -Recurse | Measure-Object Length -Sum).Sum / 1KB)
$props = @{
    DisplayName     = $title
    DisplayIcon     = "$exe,0"
    DisplayVersion  = $version
    Publisher       = $env:USERNAME
    InstallLocation = $dst
    UninstallString = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$dst\uninstall.ps1`""
}
foreach ($p in $props.GetEnumerator()) { Set-ItemProperty $key -Name $p.Key -Value $p.Value }
Set-ItemProperty $key -Name EstimatedSize -Value $size -Type DWord
Set-ItemProperty $key -Name NoModify -Value 1 -Type DWord
Set-ItemProperty $key -Name NoRepair -Value 1 -Type DWord

Write-Output "Установлено в $dst"
