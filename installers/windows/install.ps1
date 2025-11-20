# PacketSanitizer - Windows Installation Script
# Installs the PacketSanitizer plugin with prerequisite checks
# Run with: powershell -ExecutionPolicy Bypass -File install.ps1

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

function Write-Success { Write-ColorOutput Green "✓ $args" }
function Write-Warning { Write-ColorOutput Yellow "⚠ $args" }
function Write-Error { Write-ColorOutput Red "✗ $args" }
function Write-Info { Write-ColorOutput Cyan "→ $args" }
function Write-Header { Write-ColorOutput Blue $args }

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

# Check for Python 3
Write-Info "Checking for Python 3..."
$pythonFound = $false
$pythonPath = $null

# Try python command
try {
    $pythonVersion = python --version 2>&1
    if ($pythonVersion -match "Python (\d+)\.(\d+)") {
        $major = [int]$matches[1]
        $minor = [int]$matches[2]
        if ($major -ge 3 -and $minor -ge 6) {
            $pythonPath = (Get-Command python).Source
            Write-Success "Python 3 found (version: $($matches[1]).$($matches[2]))"
            $pythonFound = $true
        } else {
            Write-Error "Python 3.6+ required (found $($matches[1]).$($matches[2]))"
            $prereqFailed = $true
        }
    }
} catch {
    # Python not in PATH, try python3
    try {
        $pythonVersion = python3 --version 2>&1
        if ($pythonVersion -match "Python (\d+)\.(\d+)") {
            $major = [int]$matches[1]
            $minor = [int]$matches[2]
            if ($major -ge 3 -and $minor -ge 6) {
                $pythonPath = (Get-Command python3).Source
                Write-Success "Python 3 found (version: $($matches[1]).$($matches[2]))"
                $pythonFound = $true
            } else {
                Write-Error "Python 3.6+ required (found $($matches[1]).$($matches[2]))"
                $prereqFailed = $true
            }
        }
    } catch {
        # Check common Python locations
        $pythonPaths = @(
            "${env:LOCALAPPDATA}\Programs\Python\Python*\python.exe",
            "${env:ProgramFiles}\Python*\python.exe",
            "C:\Python*\python.exe"
        )
        
        foreach ($pathPattern in $pythonPaths) {
            $foundPaths = Get-ChildItem -Path $pathPattern -ErrorAction SilentlyContinue | Sort-Object -Descending
            if ($foundPaths) {
                foreach ($path in $foundPaths) {
                    try {
                        $version = & $path.FullName --version 2>&1
                        if ($version -match "Python (\d+)\.(\d+)") {
                            $major = [int]$matches[1]
                            $minor = [int]$matches[2]
                            if ($major -ge 3 -and $minor -ge 6) {
                                $pythonPath = $path.FullName
                                Write-Success "Python 3 found (version: $($matches[1]).$($matches[2])) at $pythonPath"
                                $pythonFound = $true
                                break
                            }
                        }
                    } catch {
                        continue
                    }
                }
                if ($pythonFound) { break }
            }
        }
        
        if (-not $pythonFound) {
            Write-Error "Python 3 not found"
            Write-Output "   Install from: https://www.python.org/downloads/"
            Write-Output "   Or via Microsoft Store: python"
            $prereqFailed = $true
        }
    }
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
    try {
        $scapyTest = & $pythonPath -c "import scapy; print(scapy.__version__)" 2>&1
        if ($scapyTest -notmatch "ModuleNotFoundError" -and $scapyTest -notmatch "ImportError") {
            if ($scapyTest -match "^\d+\.\d+") {
                Write-Success "Scapy found (version: $($scapyTest.Trim()))"
            } else {
                Write-Success "Scapy found"
            }
            $scapyFound = $true
        }
    } catch {
        # Scapy not found
    }
} else {
    try {
        $scapyTest = python -c "import scapy; print(scapy.__version__)" 2>&1
        if ($scapyTest -notmatch "ModuleNotFoundError" -and $scapyTest -notmatch "ImportError") {
            if ($scapyTest -match "^\d+\.\d+") {
                Write-Success "Scapy found (version: $($scapyTest.Trim()))"
            } else {
                Write-Success "Scapy found"
            }
            $scapyFound = $true
        }
    } catch {
        # Scapy not found
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
    try {
        $scapyTest = & $pythonPath -c "import scapy" 2>&1
        if ($scapyTest -notmatch "ModuleNotFoundError" -and $scapyTest -notmatch "ImportError") {
            Write-Success "Scapy import test passed"
        } else {
            Write-Warning "Scapy import test failed"
            Write-Output "   The plugin may not work correctly."
            Write-Output "   Try: & '$pythonPath' -m pip install scapy"
        }
    } catch {
        Write-Warning "Could not verify Scapy import"
    }
} else {
    try {
        $scapyTest = python -c "import scapy" 2>&1
        if ($scapyTest -notmatch "ModuleNotFoundError" -and $scapyTest -notmatch "ImportError") {
            Write-Success "Scapy import test passed"
        } else {
            Write-Warning "Scapy import test failed"
            Write-Output "   The plugin may not work correctly."
            Write-Output "   Try: pip install scapy"
        }
    } catch {
        Write-Warning "Could not verify Scapy import"
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
Write-Output "  2. Go to: Tools → PacketSanitizer"
Write-Output "  3. Choose a sanitization mode:"
Write-Output "     • Sanitize All Payload"
Write-Output "     • Sanitize Clear Text Payload"
Write-Output "     • Sanitize Payload and IP & MAC Addresses"
Write-Output ""
Write-Header "Plugin location:"
Write-Output "  $pluginDir\"
Write-Output ""
Write-Header "Files installed:"
Write-Output "  • PacketSanitizer.lua"
Write-Output "  • sanitize_packets.py"
Write-Output ""
Write-Header "Documentation:"
Write-Output "  • README.md - Full user guide"
Write-Output "  • INSTALL.md - Detailed installation guide"
Write-Output ""

