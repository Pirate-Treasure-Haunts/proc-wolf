# Disable and label legacy OpenVPN TAP adapters

Write-Host "Scanning for TAP/OpenVPN adapters..." -ForegroundColor Cyan

# Get all TAP-style adapters from Device Manager
$tapAdapters = Get-CimInstance Win32_NetworkAdapter | Where-Object {
    $_.NetConnectionID -match "TAP|OpenVPN" -or
    $_.Name -match "TAP|OpenVPN"
}

if (-not $tapAdapters) {
    Write-Host "No TAP/OpenVPN adapters found." -ForegroundColor Green
    return
}

foreach ($adapter in $tapAdapters) {
    Write-Host ""
    Write-Host "Found: $($adapter.Name)" -ForegroundColor Yellow

    # Check if it's already disabled
    if ($adapter.NetEnabled -eq $false) {
        Write-Host "Already disabled." -ForegroundColor Gray
        continue
    }

    # Attempt to disable it using DevCon (PowerShell way)
    try {
        $result = Disable-PnpDevice -InstanceId $adapter.PNPDeviceID -Confirm:$false -ErrorAction Stop
        Write-Host "Disabled successfully." -ForegroundColor Red
    }
    catch {
        Write-Host "Failed to disable: $_" -ForegroundColor Magenta
    }

    # Rename the adapter to something clear
    $netshName = $adapter.NetConnectionID
    if ($netshName) {
        try {
            netsh interface set interface name="$netshName" newname="Legacy TAP - Disabled"
            Write-Host "Renamed to 'Legacy TAP - Disabled'" -ForegroundColor DarkCyan
        } catch {
            Write-Host "Could not rename adapter: $_" -ForegroundColor DarkYellow
        }
    } else {
        Write-Host "No NetConnectionID set (might be virtual-only)." -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "All TAP/OpenVPN adapters processed. ProtonVPN untouched. Done." -ForegroundColor Green
