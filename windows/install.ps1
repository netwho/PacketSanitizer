# PacketSanitizer - Windows Installation Script
# Installs the PacketSanitizer plugin with prerequisite checks
# Run with: install.bat   OR   powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1

# Enable strict mode
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Colors for output
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

function Write-Success { Write-ColorOutput Green "[OK] $args" }
function Write-Warning { Write-ColorOutput Yellow "[WARN] $args" }
function Write-Error { Write-ColorOutput Red "[FAIL] $args" }
function Write-Info { Write-ColorOutput Cyan "[>>] $args" }
function Write-Header { Write-ColorOutput Blue $args }

function Get-PythonOutputLines {
    param($Output)
    if ($null -eq $Output) { return @() }
    @($Output | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.ToString() } else { "$_" }
    })
}

function Test-PythonExitCode {
    param(
        [Parameter(Mandatory = $true)]
        [string] $PythonExe,
        [Parameter(Mandatory = $true)]
        [string] $Code
    )
    $null = & $PythonExe -c $Code 2>&1
    return ($LASTEXITCODE -eq 0)
}

function Get-PythonVersionTuple {
    param([string] $VersionText)
    if ("$VersionText" -match "Python (\d+)\.(\d+)") {
        return @{ Major = [int]$Matches[1]; Minor = [int]$Matches[2] }
    }
    return $null
}

function Test-Python36Plus {
    param([string] $PythonExe)
    $verOut = & $PythonExe --version 2>&1
    if ($LASTEXITCODE -ne 0) { return $false }
    $t = Get-PythonVersionTuple "$verOut"
    if (-not $t) { return $false }
    return ($t.Major -gt 3 -or ($t.Major -eq 3 -and $t.Minor -ge 6))
}

Write-Header "============================================"
Write-Header "PacketSanitizer - Windows Installation"
Write-Header "============================================"
Write-Output ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Not running as Administrator (some checks may be limited)"
    Write-Output ""
}

# Prerequisites check
Write-Header "Checking prerequisites..."
Write-Output ""

$prereqFailed = $false

# Check for Wireshark
Write-Info "Checking for Wireshark..."
$wiresharkPaths = @(
    "${env:ProgramFiles}\Wireshark\Wireshark.exe",
    "${env:ProgramFiles(x86)}\Wireshark\Wireshark.exe"
)

$wiresharkFound = $false
$wiresharkPath = $null
foreach ($path in $wiresharkPaths) {
    if (Test-Path $path) {
        $wiresharkFound = $true
        $wiresharkPath = $path
        try {
            $versionInfo = & $path --version 2>&1 | Select-Object -First 1
            if ($versionInfo -match "Wireshark (\d+\.\d+)") {
                $version = $matches[1]
                $majorVersion = [int]($version.Split('.')[0])
                Write-Success "Wireshark found (version: $version)"
                if ($majorVersion -lt 3) {
                    Write-Warning "Wireshark 3.0+ recommended (found $version)"
                }
            } else {
                Write-Success "Wireshark found"
            }
        } catch {
            Write-Success "Wireshark found"
        }
        break
    }
}

if (-not $wiresharkFound) {
    Write-Error "Wireshark not found"
    Write-Output "   Install from: https://www.wireshark.org/download.html"
    $prereqFailed = $true
}

# Check for Python 3 (PATH, py launcher, then common install locations)
Write-Info "Checking for Python 3..."
$pythonFound = $false
$pythonPath = $null

foreach ($cmdName in @('python', 'python3')) {
    $cmd = Get-Command $cmdName -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    if (Test-Python36Plus -PythonExe $cmd.Source) {
        $verOut = & $cmd.Source --version 2>&1
        $t = Get-PythonVersionTuple "$verOut"
        $pythonPath = $cmd.Source
        Write-Success "Python 3 found (version: $($t.Major).$($t.Minor))"
        $pythonFound = $true
        break
    }
}

if (-not $pythonFound) {
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        $pyOut = & $pyLauncher.Source -3 -c "import sys; print(sys.executable)" 2>&1
        if ($LASTEXITCODE -eq 0) {
            $line = (Get-PythonOutputLines $pyOut | Where-Object { $_ -match '^[A-Za-z]:\\' } | Select-Object -First 1)
            if (-not $line) {
                $line = "$(Get-PythonOutputLines $pyOut | Select-Object -Last 1)".Trim()
            }
            if ($line -and (Test-Path -LiteralPath $line) -and (Test-Python36Plus -PythonExe $line)) {
                $verOut = & $line --version 2>&1
                $t = Get-PythonVersionTuple "$verOut"
                $pythonPath = $line
                Write-Success "Python 3 found via py launcher (version: $($t.Major).$($t.Minor)) at $pythonPath"
                $pythonFound = $true
            }
        }
    }
}

if (-not $pythonFound) {
    $pythonPaths = @(
        "${env:LOCALAPPDATA}\Programs\Python\Python*\python.exe",
        "${env:ProgramFiles}\Python310\python.exe",
        "${env:ProgramFiles}\Python311\python.exe",
        "${env:ProgramFiles}\Python312\python.exe",
        "${env:ProgramFiles}\Python313\python.exe",
        "${env:ProgramFiles}\Python314\python.exe",
        "${env:ProgramFiles}\Python*\python.exe",
        "${env:ProgramFiles(x86)}\Python*\python.exe",
        "C:\Python310\python.exe",
        "C:\Python311\python.exe",
        "C:\Python312\python.exe",
        "C:\Python313\python.exe",
        "C:\Python314\python.exe",
        "C:\Python*\python.exe"
    )

    foreach ($pathPattern in $pythonPaths) {
        $foundPaths = @(Get-ChildItem -Path $pathPattern -ErrorAction SilentlyContinue | Sort-Object { $_.FullName } -Descending)
        foreach ($path in $foundPaths) {
            if (Test-Python36Plus -PythonExe $path.FullName) {
                $verOut = & $path.FullName --version 2>&1
                $t = Get-PythonVersionTuple "$verOut"
                $pythonPath = $path.FullName
                Write-Success "Python 3 found (version: $($t.Major).$($t.Minor)) at $pythonPath"
                $pythonFound = $true
                break
            }
        }
        if ($pythonFound) { break }
    }
}

if (-not $pythonFound) {
    Write-Error "Python 3 not found (3.6+ required, on PATH or in a common install folder)"
    Write-Output "   Install from: https://www.python.org/downloads/"
    Write-Output "   Or via Microsoft Store / Python launcher (py)"
    $prereqFailed = $true
}

# Check for pip
Write-Info "Checking for pip..."
$pipFound = $false
if ($pythonPath) {
    try {
        $pipVersion = & $pythonPath -m pip --version 2>&1
        if ($pipVersion -match "pip") {
            Write-Success "pip found"
            $pipFound = $true
        }
    } catch {
        Write-Warning "pip not found (needed for Scapy installation)"
    }
} else {
    try {
        $pipVersion = pip --version 2>&1
        if ($pipVersion -match "pip") {
            Write-Success "pip found"
            $pipFound = $true
        }
    } catch {
        Write-Warning "pip not found (needed for Scapy installation)"
    }
}

# Check for Scapy
Write-Info "Checking for Scapy library..."
$scapyFound = $false
if ($pythonPath) {
    $scapyTest = & $pythonPath -c "import scapy; print(scapy.__version__)" 2>&1
    if ($LASTEXITCODE -eq 0) {
        $lines = Get-PythonOutputLines $scapyTest
        $verLine = ($lines | Where-Object { $_ -match '^\d+\.\d+' } | Select-Object -First 1)
        if ($verLine) {
            Write-Success "Scapy found (version: $verLine)"
        } else {
            Write-Success "Scapy found"
        }
        $scapyFound = $true
    }
} else {
    $scapyTest = python -c "import scapy; print(scapy.__version__)" 2>&1
    if ($LASTEXITCODE -eq 0) {
        $lines = Get-PythonOutputLines $scapyTest
        $verLine = ($lines | Where-Object { $_ -match '^\d+\.\d+' } | Select-Object -First 1)
        if ($verLine) {
            Write-Success "Scapy found (version: $verLine)"
        } else {
            Write-Success "Scapy found"
        }
        $scapyFound = $true
    }
}

if (-not $scapyFound) {
    Write-Error "Scapy not found"
    if ($pythonPath) {
        Write-Output "   Install with: & '$pythonPath' -m pip install scapy"
    } elseif ($pipFound) {
        Write-Output "   Install with: pip install scapy"
    } else {
        Write-Output "   Install with: python -m pip install scapy"
    }
    $prereqFailed = $true
}

# Exit if critical prerequisites failed
if ($prereqFailed) {
    Write-Output ""
    Write-Error "Installation cannot continue - prerequisites missing"
    Write-Output "  Please install missing prerequisites and try again."
    exit 1
}

Write-Output ""
Write-Header "Installing plugin..."
Write-Output ""

# Determine plugin directory
$pluginDir = "$env:APPDATA\Wireshark\plugins\PacketSanitizer"

Write-Success "Plugin directory: $pluginDir"

# Create plugin directory if it doesn't exist
if (-not (Test-Path $pluginDir)) {
    Write-Info "Creating plugin directory..."
    New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null
    Write-Success "Directory created"
} else {
    Write-Success "Directory exists"
}

# Find and copy the plugin files
$filesCopied = 0

# Copy PacketSanitizer.lua
$luaFile = $null
if (Test-Path "$ScriptDir\PacketSanitizer.lua") {
    $luaFile = "$ScriptDir\PacketSanitizer.lua"
} elseif (Test-Path "$ScriptDir\..\..\PacketSanitizer.lua") {
    $luaFile = "$ScriptDir\..\..\PacketSanitizer.lua"
}

if ($luaFile) {
    Write-Info "Installing PacketSanitizer.lua..."
    Copy-Item $luaFile "$pluginDir\PacketSanitizer.lua" -Force
    Write-Success "PacketSanitizer.lua installed"
    $filesCopied++
} else {
    Write-Error "PacketSanitizer.lua not found"
}

# Copy sanitize_packets.py
$pyFile = $null
if (Test-Path "$ScriptDir\sanitize_packets.py") {
    $pyFile = "$ScriptDir\sanitize_packets.py"
} elseif (Test-Path "$ScriptDir\..\..\sanitize_packets.py") {
    $pyFile = "$ScriptDir\..\..\sanitize_packets.py"
}

if ($pyFile) {
    Write-Info "Installing sanitize_packets.py..."
    Copy-Item $pyFile "$pluginDir\sanitize_packets.py" -Force
    Write-Success "sanitize_packets.py installed"
    $filesCopied++
} else {
    Write-Error "sanitize_packets.py not found"
}

# Verify installation
if ($filesCopied -lt 2) {
    Write-Output ""
    Write-Error "Installation incomplete - not all files were copied"
    exit 1
}

# Verify Python can find Scapy
Write-Output ""
Write-Header "Verifying installation..."
Write-Output ""

if ($pythonPath) {
    if (Test-PythonExitCode -PythonExe $pythonPath -Code "import scapy") {
        Write-Success "Scapy import test passed"
    } else {
        Write-Warning "Scapy import test failed"
        Write-Output "   The plugin may not work correctly."
        Write-Output "   Try: & '$pythonPath' -m pip install scapy"
    }
} else {
    if (Test-PythonExitCode -PythonExe "python" -Code "import scapy") {
        Write-Success "Scapy import test passed"
    } else {
        Write-Warning "Scapy import test failed"
        Write-Output "   The plugin may not work correctly."
        Write-Output "   Try: pip install scapy"
    }
}

# Final instructions
Write-Output ""
Write-Header "============================================"
Write-Success "Installation Complete!"
Write-Header "============================================"
Write-Output ""
Write-Header "Next steps:"
Write-Output "  1. Restart Wireshark"
Write-Output "  2. Go to: Tools > PacketSanitizer"
Write-Output "  3. Choose a sanitization mode:"
Write-Output "     - Sanitize All Payload"
Write-Output "     - Sanitize Clear Text Payload"
Write-Output "     - Sanitize Payload and IP & MAC Addresses"
Write-Output ""
Write-Header "Plugin location:"
Write-Output "  $pluginDir\"
Write-Output ""
Write-Header "Files installed:"
Write-Output "  - PacketSanitizer.lua"
Write-Output "  - sanitize_packets.py"
Write-Output ""
Write-Header "Documentation:"
Write-Output "  - README.md - Full user guide"
Write-Output "  - INSTALL.md - Detailed installation guide"
Write-Output ""

