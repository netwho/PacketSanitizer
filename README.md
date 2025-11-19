# PacketSanitizer

![Version](https://img.shields.io/badge/version-0.0.2-blue.svg)
![License](https://img.shields.io/badge/license-GPL%20v2-green.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)
![Python](https://img.shields.io/badge/python-3.6%2B-blue.svg)
![Wireshark](https://img.shields.io/badge/wireshark-3.0%2B-orange.svg)

A Wireshark Lua plugin for sanitizing PCAP/PCAPNG files for safe sharing outside organizations.

## Description

PacketSanitizer is a Wireshark plugin that sanitizes packet capture files by:
- **Anonymizing IP addresses** - Replaces all IPs with anonymized versions while maintaining conversation flows
- **Anonymizing MAC addresses** - Replaces all MAC addresses with anonymized versions
- **Removing DHCP data** - Completely removes DHCP layer information
- **Sanitizing payloads** - Replaces UDP and TCP payload data with a recognizable pattern (0x5341 = "SA" for "Sanitized") while preserving packet size
- **Preserving structure** - Maintains full packet structure and size for analysis while removing sensitive data

The original file is preserved, and a sanitized copy is created with the `_sanitized` suffix.

## Screenshots

### Wireshark Menu Integration

The PacketSanitizer plugin appears in Wireshark's Tools menu:

![Wireshark Menu](examples/Sanitize.png)

### Sanitization Process

When you select "Sanitize PCAP(NG)" from the Tools menu, the plugin will:
1. Detect the current capture file (or prompt you to select one)
2. Process all packets to sanitize sensitive data
3. Display a success message with an option to open the sanitized file

![Success Dialog](examples/PacketSanitizer-Success.png)

### Before and After Comparison

**Before Sanitization:**
- Original IP addresses visible
- Original MAC addresses visible
- Payload data contains real information

**After Sanitization:**
- IP addresses anonymized (maintaining conversation flows)
- MAC addresses anonymized
- Payload data replaced with "SA" pattern (0x5341)
- DHCP information removed
- IGMP packets left untouched

![Before/After Comparison](examples/PacketSanitizer-Comparison.png)

## Installation

### Prerequisites

1. **Python 3** (3.6 or later)
2. **Scapy library**:
   ```bash
   pip3 install scapy
   ```
   
   **macOS Quick Install (if you get "externally-managed-environment" error):**
   ```bash
   pip3 install --break-system-packages scapy
   ```
   
   Or install from requirements:
   ```bash
   pip3 install -r requirements.txt
   ```

### Wireshark Plugin Installation

**Important:** Both `PacketSanitizer.lua` and `sanitize_packets.py` must be in the same directory for the plugin to work. The Lua script automatically finds the Python script in its own directory.

1. Copy the entire PacketSanitizer directory (containing both files) to your Wireshark plugins directory:
   
   **Linux/macOS:**
   ```bash
   cp -r PacketSanitizer ~/.local/lib/wireshark/plugins/
   chmod +x ~/.local/lib/wireshark/plugins/PacketSanitizer/sanitize_packets.py
   ```
   
   **Windows:**
   ```cmd
   xcopy PacketSanitizer "%APPDATA%\Wireshark\plugins\PacketSanitizer\" /E /I
   ```

2. Restart Wireshark

**How it works:**
- The Lua script (`PacketSanitizer.lua`) provides the Wireshark menu integration
- When you click "Tools → PacketSanitizer → Sanitize Current File", the Lua script:
  1. Finds the Python script in the same directory as the Lua script
  2. Executes `python3 sanitize_packets.py <input> <output>`
  3. Shows the result in a Wireshark text window

## Usage

1. Open a PCAP/PCAPNG file in Wireshark
2. Go to **Tools → PacketSanitizer → Sanitize Current File**
3. The sanitized file will be created in the same directory with `_sanitized.pcap` suffix
4. The original file remains unchanged

### Command Line Usage

You can also use the Python script directly:

```bash
python3 sanitize_packets.py input.pcap output_sanitized.pcap
```

## How It Works

### IP Address Anonymization
- All IP addresses are replaced with addresses from the `10.0.0.0/8` range
- The same original IP always maps to the same anonymized IP (maintains conversation flows)
- IPv4 and IPv6 are both supported

### MAC Address Anonymization
- All MAC addresses are replaced with locally administered MACs (`02:00:00:00:00:XX`)
- The same original MAC always maps to the same anonymized MAC (maintains device identity)

### Payload Sanitization
- TCP and UDP payloads are replaced with a sanitized pattern (0x5341: `0x53 0x41` = "SA" for "Sanitized")
- Uses printable ASCII characters (0x20-0x7E range) for better readability
- Original packet size is preserved (pattern is repeated to match original payload length)
- Full packet structure is maintained, including headers and payload space
- Packet timing and structure are preserved

### DHCP Removal
- DHCP layer is completely removed from packets
- No DHCP information is preserved in the sanitized file

## Requirements

- Wireshark 3.0 or later
- Lua support enabled in Wireshark
- Python 3.6 or later
- Scapy library

## File Structure

```
PacketSanitizer/
├── PacketSanitizer.lua    # Wireshark Lua plugin (menu integration)
├── sanitize_packets.py    # Python script (packet sanitization)
├── requirements.txt       # Python dependencies
├── README.md             # This file
└── INSTALL.md            # Detailed installation guide
```

**How the plugin works:**
1. `PacketSanitizer.lua` is loaded by Wireshark and adds a menu item under "Tools"
2. When clicked, the Lua script finds `sanitize_packets.py` in the same directory
3. The Lua script executes: `python3 sanitize_packets.py <input_file> <output_file>`
4. The Python script uses Scapy to sanitize the packets
5. Results are shown in a Wireshark text window

## Security Notes

- The sanitized file removes sensitive data but may still contain:
  - Protocol headers and structure
  - Packet timing information
  - Port numbers
  - Protocol types
- Review the sanitized file before sharing
- Consider additional sanitization for highly sensitive environments

## License

This project is licensed under the GNU General Public License v2 (GPL v2).

See [LICENSE](LICENSE) file for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

