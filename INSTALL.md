# Installation Guide

## Quick Installation (Recommended)

We provide automated installers for macOS, Linux, and Windows that check all prerequisites and install the plugin automatically.

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

The installers will:
- ✅ Check for Wireshark 3.0+
- ✅ Check for Python 3.6+
- ✅ Check for Scapy library
- ✅ Check for optional file dialog tools (Linux)
- ✅ Create plugin directory
- ✅ Copy plugin files
- ✅ Verify installation

For detailed installer documentation, see [installers/README.md](installers/README.md).

## Prerequisites

### Required (All Platforms)

1. **Wireshark 3.0 or later**
   - **macOS**: Download from [wireshark.org](https://www.wireshark.org/download.html) or install via Homebrew: `brew install --cask wireshark`
   - **Linux**: Install via package manager:
     - Debian/Ubuntu: `sudo apt install wireshark`
     - Fedora/RHEL: `sudo dnf install wireshark`
     - Arch: `sudo pacman -S wireshark-qt`
     - openSUSE: `sudo zypper install wireshark`
   - **Windows**: Download installer from [wireshark.org](https://www.wireshark.org/download.html)

2. **Python 3.6 or later**
   - **macOS**: Usually pre-installed, or install via Homebrew: `brew install python3`
   - **Linux**: Usually pre-installed, or install via package manager:
     - Debian/Ubuntu: `sudo apt install python3`
     - Fedora/RHEL: `sudo dnf install python3`
     - Arch: `sudo pacman -S python`
     - openSUSE: `sudo zypper install python3`
   - **Windows**: Download from [python.org](https://www.python.org/downloads/) or install via Microsoft Store

3. **Scapy library**
   ```bash
   # macOS/Linux
   pip3 install scapy
   
   # macOS (if you get "externally-managed-environment" error)
   pip3 install --break-system-packages scapy
   
   # Windows
   pip install scapy
   ```
   
   Or install from requirements:
   ```bash
   pip3 install -r requirements.txt
   ```

### Optional (Recommended for Better Experience)

#### Linux: File Dialog Tools

For GUI file selection in the plugin, install one of these (optional but recommended):

- **zenity** (GNOME/GTK-based systems):
  - Debian/Ubuntu: `sudo apt install zenity`
  - Fedora/RHEL: `sudo dnf install zenity`
  - Arch: `sudo pacman -S zenity`
  - openSUSE: `sudo zypper install zenity`

- **kdialog** (KDE systems):
  - Usually comes with KDE desktop environment
  - Can be installed separately if needed

- **yad** (Alternative):
  - Debian/Ubuntu: `sudo apt install yad`
  - Fedora/RHEL: `sudo dnf install yad`

**Note**: The plugin will still work without these tools. You can use command-line mode or open files directly in Wireshark first.

## Manual Installation

If you prefer to install manually or the automated installer doesn't work:

### macOS/Linux

1. **Install Python dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```
   
   Or manually:
   ```bash
   pip3 install scapy
   ```

2. **Create plugin directory:**
   ```bash
   mkdir -p ~/.local/lib/wireshark/plugins/PacketSanitizer
   ```

3. **Copy plugin files:**
   ```bash
   cp PacketSanitizer.lua ~/.local/lib/wireshark/plugins/PacketSanitizer/
   cp sanitize_packets.py ~/.local/lib/wireshark/plugins/PacketSanitizer/
   chmod +x ~/.local/lib/wireshark/plugins/PacketSanitizer/sanitize_packets.py
   ```

4. **Restart Wireshark**

### Windows

1. **Install Python dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```
   
   Or manually:
   ```powershell
   pip install scapy
   ```

2. **Create plugin directory:**
   ```powershell
   New-Item -ItemType Directory -Path "$env:APPDATA\Wireshark\plugins\PacketSanitizer" -Force
   ```

3. **Copy plugin files:**
   ```powershell
   Copy-Item PacketSanitizer.lua "$env:APPDATA\Wireshark\plugins\PacketSanitizer\"
   Copy-Item sanitize_packets.py "$env:APPDATA\Wireshark\plugins\PacketSanitizer\"
   ```

4. **Restart Wireshark**

**Important:** Both `PacketSanitizer.lua` and `sanitize_packets.py` must be in the same directory. The Lua script automatically locates the Python script in its own directory.

## Installation Locations

The plugin files should be installed in:

| Platform | Directory |
|----------|-----------|
| **macOS** | `~/.local/lib/wireshark/plugins/PacketSanitizer/` |
| **Linux** | `~/.local/lib/wireshark/plugins/PacketSanitizer/` |
| **Windows** | `%APPDATA%\Wireshark\plugins\PacketSanitizer\` |

## Verification

1. **Restart Wireshark** (required after installation)

2. **Check the menu:**
   - Go to **Tools → PacketSanitizer**
   - You should see three submenu options:
     - Sanitize All Payload
     - Sanitize Clear Text Payload
     - Sanitize Payload and IP & MAC Addresses

3. **Check plugin version:**
   - Go to **Help → About Wireshark → Plugins**
   - Look for "PacketSanitizer" with version 0.1.1

4. **Check plugin location:**
   - Go to **Help → About Wireshark → Folders**
   - Verify the plugins directory path

## Troubleshooting

### Plugin Not Appearing in Menu

1. **Check plugin location:**
   - Verify files are in the correct directory (see Installation Locations above)
   - Ensure both `PacketSanitizer.lua` and `sanitize_packets.py` are present

2. **Check file permissions (macOS/Linux):**
   ```bash
   ls -la ~/.local/lib/wireshark/plugins/PacketSanitizer/
   chmod 644 ~/.local/lib/wireshark/plugins/PacketSanitizer/PacketSanitizer.lua
   chmod 755 ~/.local/lib/wireshark/plugins/PacketSanitizer/sanitize_packets.py
   ```

3. **Check Wireshark Lua support:**
   - Go to **Help → About Wireshark**
   - Look for "with Lua" in the version information

4. **Check for errors:**
   - Open Wireshark console: **View → Internals → Lua**
   - Look for error messages related to PacketSanitizer

### Python Script Not Found

1. **Verify Python script location:**
   - Ensure `sanitize_packets.py` is in the same directory as `PacketSanitizer.lua`
   - Check the exact path shown in the error message

2. **Check file permissions (macOS/Linux):**
   ```bash
   chmod +x ~/.local/lib/wireshark/plugins/PacketSanitizer/sanitize_packets.py
   ```

3. **Verify Python 3 is accessible:**
   ```bash
   # macOS/Linux
   python3 --version
   which python3
   
   # Windows
   python --version
   where python
   ```

### Scapy Import Errors

1. **Verify Scapy installation:**
   ```bash
   # macOS/Linux
   python3 -c "import scapy; print(scapy.__version__)"
   
   # Windows
   python -c "import scapy; print(scapy.__version__)"
   ```

2. **Reinstall Scapy if needed:**
   ```bash
   # macOS/Linux
   pip3 install --upgrade scapy
   
   # macOS (if you get "externally-managed-environment" error)
   pip3 install --break-system-packages --upgrade scapy
   
   # Windows
   pip install --upgrade scapy
   ```

3. **Check Python path:**
   - The plugin automatically finds Python, but if issues persist, verify the Python that has Scapy installed is in your PATH

### File Dialog Not Working (Linux)

If the file selection dialog doesn't work on Linux:

1. **Check if a dialog tool is installed:**
   ```bash
   which zenity kdialog yad
   ```

2. **Install a dialog tool:**
   ```bash
   # Debian/Ubuntu
   sudo apt install zenity
   
   # Fedora/RHEL
   sudo dnf install zenity
   
   # Arch
   sudo pacman -S zenity
   ```

3. **Alternative**: The plugin will still work - you can:
   - Open the file in Wireshark first, then use the plugin
   - Use command-line mode (see README.md for examples)

### Windows-Specific Issues

1. **PowerShell execution policy:**
   - If the installer fails, you may need to adjust execution policy:
     ```powershell
     Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
     ```

2. **Python not in PATH:**
   - During Python installation, make sure to check "Add Python to PATH"
   - Or manually add Python to your system PATH

3. **Wireshark not found:**
   - Verify Wireshark is installed in the standard location:
     - `C:\Program Files\Wireshark\` (64-bit)
     - `C:\Program Files (x86)\Wireshark\` (32-bit)

## Uninstallation

To remove the plugin:

1. **Delete the plugin directory:**
   ```bash
   # macOS/Linux
   rm -rf ~/.local/lib/wireshark/plugins/PacketSanitizer
   
   # Windows
   Remove-Item -Recurse -Force "$env:APPDATA\Wireshark\plugins\PacketSanitizer"
   ```

2. **Restart Wireshark**

The plugin will no longer appear in the Tools menu.

## Additional Resources

- **README.md** - Full user guide and feature documentation
- **installers/README.md** - Detailed installer documentation
- **CONTRIBUTING.md** - Contribution guidelines
