# Nuke Earn.FM - Full Scorch Script for PowerShell
Write-Host "Scanning and nuking Earn.FM remnants..." -ForegroundColor Cyan

# Step 1: Kill known processes
$processes = "earnfm", "earn.fm", "earn_fm"
foreach ($p in $processes) {
    Get-Process | Where-Object { $_.Name -like "*$p*" } | ForEach-Object {
        Write-Host "Killing process: $($_.Name)" -ForegroundColor Yellow
        Stop-Process -Id $_.Id -Force
    }
}

# Step 2: Delete related folders and files
$foldersToDelete = @(
    "$env:USERPROFILE\Documents\info.hive",
    "$env:USERPROFILE\Documents\settingsbox.hive",
    "$env:USERPROFILE\Documents\info.lock",
    "$env:USERPROFILE\Documents\settingsbox.lock",
    "$env:USERPROFILE\Documents\logs.zip",
    "$env:LOCALAPPDATA\Earn.FM",
    "$env:APPDATA\Earn.FM",
    "$env:USERPROFILE\AppData\Roaming\Earn.FM",
    "$env:USERPROFILE\AppData\Local\Programs\Earn.FM",
    "$env:TEMP\earnfm",
    "$env:TEMP\earn.fm",
    "$env:LOCALAPPDATA\Temp\earnfm"
)

foreach ($folder in $foldersToDelete) {
    if (Test-Path $folder) {
        Write-Host "Removing: $folder" -ForegroundColor Red
        Remove-Item $folder -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Step 3: Check browser extension folders
$browserPaths = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions",
    "$env:APPDATA\Mozilla\Firefox\Profiles"
)

foreach ($path in $browserPaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Recurse -Directory | Where-Object {
            $_.Name -match "earnfm|earn.fm"
        } | ForEach-Object {
            Write-Host "Purging extension dir: $($_.FullName)" -ForegroundColor Red
            Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Step 4: Registry cleanup
$registryPaths = @(
    "HKCU:\Software\Earn.FM",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Earn.FM",
    "HKCU:\Software\Classes\earnfm",
    "HKCU:\Software\Classes\earn.fm"
)

foreach ($reg in $registryPaths) {
    if (Test-Path $reg) {
        Write-Host "Removing registry key: $reg" -ForegroundColor DarkRed
        Remove-Item -Path $reg -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`nAll known Earn.FM artifacts have been removed." -ForegroundColor Green
Write-Host "If you're feeling extra cautious, reboot and rerun to confirm nothing regenerated." -ForegroundColor Gray
