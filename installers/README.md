# PacketSanitizer Installers

This directory contains installation scripts for macOS and Linux that automatically check prerequisites and install the PacketSanitizer plugin.

## Quick Start

### macOS

```bash
cd installers/macos
./install.sh
```

### Linux

```bash
cd installers/linux
./install.sh
```

### Windows

```powershell
cd installers\windows
powershell -ExecutionPolicy Bypass -File install.ps1
```

## What the Installers Do

### Prerequisites Check

The installers verify the following prerequisites:

1. **Wireshark 3.0+** - Network protocol analyzer
   - Checks if Wireshark is installed
   - Verifies version compatibility

2. **Python 3.6+** - Required for packet sanitization
   - Checks Python version
   - Verifies Python is accessible

3. **Scapy Library** - Python library for packet manipulation
   - Checks if Scapy is installed
   - Provides installation instructions if missing

4. **Lua** (Linux only) - Usually bundled with Wireshark
   - Checks for Lua availability

### Installation Process

1. **Creates plugin directory** - `~/.local/lib/wireshark/plugins/PacketSanitizer/`
2. **Copies plugin files**:
   - `PacketSanitizer.lua` - Wireshark menu integration
   - `sanitize_packets.py` - Python sanitization script
3. **Sets correct permissions** - Makes Python script executable
4. **Verifies installation** - Tests Scapy import

## Prerequisites Installation

### macOS

If prerequisites are missing, the installer will provide instructions:

**Wireshark:**
```bash
# Download from: https://www.wireshark.org/download.html
# Or install via Homebrew:
brew install --cask wireshark
```

**Python 3:**
```bash
brew install python3
```

**Scapy:**
```bash
pip3 install scapy
# Or if you get "externally-managed-environment" error:
pip3 install --break-system-packages scapy
```

### Linux

The installer detects your package manager and provides specific instructions:

**Debian/Ubuntu (apt):**
```bash
sudo apt install wireshark python3 python3-pip
pip3 install scapy
# Or use system package:
sudo apt install python3-scapy
```

**Fedora/RHEL (dnf):**
```bash
sudo dnf install wireshark python3 python3-pip
pip3 install scapy
# Or use system package:
sudo dnf install python3-scapy
```

**Arch Linux (pacman):**
```bash
sudo pacman -S wireshark-qt python python-pip
pip install scapy
# Or use system package:
sudo pacman -S python-scapy
```

**openSUSE (zypper):**
```bash
sudo zypper install wireshark python3 python3-pip
pip3 install scapy
# Or use system package:
sudo zypper install python3-scapy
```

### Windows

**Python 3:**
- Download from: https://www.python.org/downloads/
- Or install via Microsoft Store: `python`
- Make sure to check "Add Python to PATH" during installation

**Scapy:**
```powershell
pip install scapy
# Or if using specific Python:
python -m pip install scapy
```

**Wireshark:**
- Download from: https://www.wireshark.org/download.html
- Run the installer
- Include "Install WinPcap/Npcap" for packet capture

## Manual Installation

If you prefer to install manually:

### macOS/Linux

1. **Create plugin directory:**
   ```bash
   mkdir -p ~/.local/lib/wireshark/plugins/PacketSanitizer
   ```

2. **Copy files:**
   ```bash
   cp PacketSanitizer.lua ~/.local/lib/wireshark/plugins/PacketSanitizer/
   cp sanitize_packets.py ~/.local/lib/wireshark/plugins/PacketSanitizer/
   chmod 755 ~/.local/lib/wireshark/plugins/PacketSanitizer/sanitize_packets.py
   ```

3. **Restart Wireshark**

### Windows

1. **Create plugin directory:**
   ```powershell
   New-Item -ItemType Directory -Path "$env:APPDATA\Wireshark\plugins\PacketSanitizer" -Force
   ```

2. **Copy files:**
   ```powershell
   Copy-Item PacketSanitizer.lua "$env:APPDATA\Wireshark\plugins\PacketSanitizer\"
   Copy-Item sanitize_packets.py "$env:APPDATA\Wireshark\plugins\PacketSanitizer\"
   ```

3. **Restart Wireshark**

## Verification

After installation, verify the plugin:

1. **Restart Wireshark**
2. **Check plugin location:**
   ```bash
   ls -la ~/.local/lib/wireshark/plugins/PacketSanitizer/
   ```
3. **Check Wireshark menu:**
   - Go to **Tools → PacketSanitizer**
   - You should see three submenu options
4. **Check About Plugins:**
   - Go to **Help → About Wireshark → Plugins**
   - Look for "PacketSanitizer" with version 0.1.1

## Troubleshooting

### Plugin Not Appearing in Wireshark

1. **Check plugin location:**
   ```bash
   ls -la ~/.local/lib/wireshark/plugins/PacketSanitizer/
   ```
   Both files should be present.

2. **Check file permissions:**
   ```bash
   chmod 644 ~/.local/lib/wireshark/plugins/PacketSanitizer/PacketSanitizer.lua
   chmod 755 ~/.local/lib/wireshark/plugins/PacketSanitizer/sanitize_packets.py
   ```

3. **Check Wireshark Lua support:**
   - Go to **Help → About Wireshark**
   - Look for "with Lua" in version info

4. **Check for errors:**
   - Open Wireshark console: **View → Internals → Lua**
   - Look for error messages

### Scapy Not Found

If the plugin reports "ModuleNotFoundError: No module named 'scapy'":

1. **Verify Scapy installation:**
   ```bash
   python3 -c "import scapy; print(scapy.__version__)"
   ```

2. **Install Scapy:**
   ```bash
   pip3 install scapy
   ```

3. **Verify Python path:**
   - The Lua script automatically finds the correct Python executable
   - If issues persist, check which Python has Scapy:
     ```bash
     which python3
     python3 -c "import scapy"
     ```

### Permission Denied

If you get "Permission denied" errors:

1. **Make installer executable:**
   ```bash
   chmod +x install.sh
   ```

2. **Check directory permissions:**
   ```bash
   ls -ld ~/.local/lib/wireshark/plugins/
   ```

## File Structure

```
installers/
├── README.md                    # This file
├── macos/
│   ├── install.sh              # macOS installer script
│   ├── PacketSanitizer.lua     # Plugin Lua file
│   └── sanitize_packets.py      # Python sanitization script
├── linux/
│   ├── install.sh               # Linux installer script
│   ├── PacketSanitizer.lua      # Plugin Lua file
│   └── sanitize_packets.py      # Python sanitization script
└── windows/
    ├── install.ps1              # Windows installer script (PowerShell)
    ├── PacketSanitizer.lua      # Plugin Lua file
    └── sanitize_packets.py      # Python sanitization script
```

## Support

For more information, see:
- **README.md** - Full user guide
- **INSTALL.md** - Detailed installation guide
- **CONTRIBUTING.md** - Contribution guidelines

