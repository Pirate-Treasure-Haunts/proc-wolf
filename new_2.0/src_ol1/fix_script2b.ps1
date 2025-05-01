# Alternative fix for PyWin32 issues

# 1. First, complete uninstall of pywin32
pip uninstall -y pywin32

# 2. Install from wheel directly
# For Python 3.12, 64-bit Windows
pip install https://github.com/mhammond/pywin32/releases/download/b306/pywin32-306-cp312-cp312-win_amd64.whl

# 3. Add the necessary paths manually since we can't run the post-install script
# Run this script as Administrator

$pythonPath = "C:\Program Files\Python312"
$sitePackages = "$pythonPath\Lib\site-packages"

# Create the necessary directories
if (-not (Test-Path "$sitePackages\win32")) {
    New-Item -ItemType Directory -Path "$sitePackages\win32" -Force
}

if (-not (Test-Path "$sitePackages\win32com")) {
    New-Item -ItemType Directory -Path "$sitePackages\win32com" -Force
}

if (-not (Test-Path "$pythonPath\Lib\site-packages\pywin32_system32")) {
    New-Item -ItemType Directory -Path "$pythonPath\Lib\site-packages\pywin32_system32" -Force
}

# Copy DLLs to the Windows system directory
$sysDLLs = Get-ChildItem -Path "$sitePackages\pywin32_system32\*.dll" -ErrorAction SilentlyContinue
foreach ($dll in $sysDLLs) {
    Write-Host "Copying $($dll.Name) to system32..."
    Copy-Item -Path $dll.FullName -Destination "C:\Windows\System32\" -Force
}

# Register the .pyd files
$pydFiles = Get-ChildItem -Path "$sitePackages\win32\*.pyd" -ErrorAction SilentlyContinue
foreach ($pyd in $pydFiles) {
    Write-Host "Registering $($pyd.Name)..."
    Start-Process "regsvr32.exe" -ArgumentList "/s $($pyd.FullName)" -Wait
}

$pydFiles = Get-ChildItem -Path "$sitePackages\win32com\*.pyd" -ErrorAction SilentlyContinue
foreach ($pyd in $pydFiles) {
    Write-Host "Registering $($pyd.Name)..."
    Start-Process "regsvr32.exe" -ArgumentList "/s $($pyd.FullName)" -Wait
}

Write-Host "PyWin32 manual setup complete!"