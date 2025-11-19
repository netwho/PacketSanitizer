# Installation Guide

## Quick Installation

**Important:** Both `PacketSanitizer.lua` and `sanitize_packets.py` must be in the same directory. The Lua script automatically locates the Python script in its own directory.

### Linux/macOS

1. **Install Python dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

2. **Copy entire PacketSanitizer directory to Wireshark plugins:**
   ```bash
   mkdir -p ~/.local/lib/wireshark/plugins
   cp -r PacketSanitizer ~/.local/lib/wireshark/plugins/
   chmod +x ~/.local/lib/wireshark/plugins/PacketSanitizer/sanitize_packets.py
   ```
   
   This copies both:
   - `PacketSanitizer.lua` (Wireshark menu integration)
   - `sanitize_packets.py` (packet sanitization engine)

3. **Restart Wireshark**

### Windows

1. **Install Python dependencies:**
   ```cmd
   pip install -r requirements.txt
   ```

2. **Copy entire PacketSanitizer directory to Wireshark plugins:**
   ```cmd
   xcopy PacketSanitizer "%APPDATA%\Wireshark\plugins\PacketSanitizer\" /E /I
   ```
   
   This copies both:
   - `PacketSanitizer.lua` (Wireshark menu integration)
   - `sanitize_packets.py` (packet sanitization engine)

3. **Restart Wireshark**

## Verification

1. Open Wireshark
2. Check that **Tools → PacketSanitizer → Sanitize Current File** appears in the menu
3. If not visible, check Wireshark's Lua console for errors:
   - **Help → About Wireshark → Folders → Personal Lua Plugins**

## Troubleshooting

### Plugin not appearing in menu

- Check that the Lua script is in the correct plugins directory
- Verify Lua is enabled in Wireshark: **Edit → Preferences → Protocols → Lua**
- Check Wireshark's Lua console for error messages

### Python script not found

- Ensure `sanitize_packets.py` is in the same directory as `PacketSanitizer.lua`
- Check file permissions (Linux/macOS): `chmod +x sanitize_packets.py`
- Verify Python 3 is in your PATH: `python3 --version`

### Scapy import errors

- Install Scapy: `pip3 install scapy`
- Verify installation: `python3 -c "import scapy; print(scapy.__version__)"`

