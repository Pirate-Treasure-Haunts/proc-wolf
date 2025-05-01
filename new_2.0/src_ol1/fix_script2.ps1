# Run this in PowerShell to find the pywin32_postinstall.py script
$pythonPath = "C:\Program Files\Python312"
Write-Host "Searching for pywin32_postinstall.py in $pythonPath..."

# Search in various possible locations
$locations = @(
    "$pythonPath\Lib\site-packages\pywin32_system32",
    "$pythonPath\Lib\site-packages\win32",
    "$pythonPath\Lib\site-packages\pywin32_system32\scripts",
    "$pythonPath\Lib\site-packages\pywin32",
    "$pythonPath\Scripts"
)

$found = $false
foreach ($loc in $locations) {
    Write-Host "Checking $loc..."
    $script = "$loc\pywin32_postinstall.py"
    if (Test-Path $script) {
        Write-Host "FOUND: $script" -ForegroundColor Green
        $found = $true
    }
    
    # Also search recursively one level down
    if (Test-Path $loc) {
        Get-ChildItem -Path $loc -Filter "pywin32_postinstall.py" -Recurse -Depth 1 | ForEach-Object {
            Write-Host "FOUND: $($_.FullName)" -ForegroundColor Green
            $found = $true
        }
    }
}

if (-not $found) {
    Write-Host "Script not found in common locations." -ForegroundColor Red
    Write-Host "Let's do a deeper search..."
    
    # Do a deeper search
    if (Test-Path $pythonPath) {
        Write-Host "Searching entire Python directory (this may take a moment)..."
        Get-ChildItem -Path $pythonPath -Filter "pywin32_postinstall.py" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "FOUND: $($_.FullName)" -ForegroundColor Green
            $found = $true
        }
    }
}

if (-not $found) {
    Write-Host "Post-install script not found. Let's try a different approach." -ForegroundColor Yellow
}