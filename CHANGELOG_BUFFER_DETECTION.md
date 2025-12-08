# PacketSanitizer v0.1.1 Update: Packet Buffer Detection

## Overview
Enhanced the PacketSanitizer Wireshark plugin to automatically detect and use packets currently in the Wireshark buffer instead of always requiring manual file selection via file dialog.

## Changes Made

### 1. New Helper Functions Added

#### `get_timestamp_filename()`
- Generates timestamp-formatted filename for temporary captures
- Format: `Capture_YYYYMMDD_HHMMSS`
- Used for temporary packet buffer exports

#### `get_temp_dir()`
- Returns platform-specific temporary directory
- Windows: Uses `TEMP`, `TMP`, or defaults to `C:\Windows\Temp`
- Unix-like (macOS/Linux): Uses `TMPDIR`, `TMP`, or defaults to `/tmp`

#### `has_packets_in_buffer()`
- Checks if packets are currently loaded in Wireshark
- **Method 1**: Checks `CaptureInfo.nr_packets` to see if capture file is open with packets
- **Method 2**: Attempts to iterate through `frameInfo()` to detect loaded packets
- Returns `true` if packets are available, `false` otherwise

#### `export_packets_to_temp()`
- Exports current packet buffer to a temporary file
- Currently uses the file path from `CaptureInfo.file` if available
- Returns the file path for further processing
- Includes placeholder code for future `dumpcap`/`tshark` integration (commented)

### 2. Updated `sanitize_capture()` Function

Modified the packet source detection logic with the following priority:

**Step 1: Buffer Detection**
- Checks if packets are available in the current Wireshark buffer using `has_packets_in_buffer()`
- If packets found, attempts to export them via `export_packets_to_temp()`
- Sets `is_temp_file` flag accordingly

**Step 2: CaptureInfo Fallback**
- If no packets in buffer, tries to get file path from `CaptureInfo.file`
- This handles cases where a file is open but buffer detection fails

**Step 3: File Dialog**
- Only shows file dialog if no packets are found and no file is open
- Maintains backward compatibility with existing workflow

### 3. Enhanced Success Message

Success message now displays:
- **Sanitization mode** used (All Payloads, Clear Text Only, or Full Sanitization)
- **Source information**:
  - If from buffer: "Packets from buffer (Capture_YYYYMMDD_HHMMSS.pcapng)"
  - If from file: Shows the original file path
- **Output location**: Path to the sanitized output file
- Open File button to load sanitized file in Wireshark

### 4. Platform Support

All helper functions include platform-specific implementations:
- **Windows**: Uses `TEMP` environment variable, PowerShell compatibility
- **macOS**: Uses `TMPDIR`, proper path handling
- **Linux**: Standard `/tmp` directory with fallback options

## Benefits

1. **Improved User Experience**: Users can now sanitize packets without file dialogs when packets are already loaded
2. **Workflow Efficiency**: Stopped captures or loaded files are automatically detected and used
3. **Timestamp Tracking**: Temporary captures are timestamped for easy identification
4. **Backward Compatible**: Falls back to file dialog if no packets are detected
5. **Cross-Platform**: Works on Windows, macOS, and Linux

## Usage Scenarios

### Scenario 1: Active Capture
1. User captures packets in Wireshark
2. Clicks "Tools → PacketSanitizer → [Mode]"
3. Plugin detects buffered packets and sanitizes them immediately
4. No file dialog shown

### Scenario 2: Loaded PCAP File
1. User opens existing PCAP file in Wireshark
2. Clicks "Tools → PacketSanitizer → [Mode]"
3. Plugin detects loaded packets and uses the file
4. No file dialog shown

### Scenario 3: No Packets (Legacy Behavior)
1. User has no packets loaded in Wireshark
2. Clicks "Tools → PacketSanitizer → [Mode]"
3. Plugin shows file dialog (existing behavior preserved)
4. User selects PCAP file to process

## Technical Notes

### Wireshark Lua API Usage
- `CaptureInfo`: Contains capture file information (`file`, `nr_packets`)
- `frameInfo()`: Iterator for accessing packet frames
- `gui_enabled()`: Checks if GUI is available (required for plugin)
- `os.date()`: For timestamp generation
- `os.getenv()`: For environment variable access

### Future Enhancement Opportunities
1. **Live Capture Export**: Implement `dumpcap` integration to export active captures
2. **Filtered Packets**: Add support for exporting filtered packet views
3. **Multi-File Processing**: Support batch processing of multiple captures
4. **Progress Indicator**: Show progress during large capture processing

## Files Modified

- `/PacketSanitizer.lua` - Main plugin file
- `/installers/macos/PacketSanitizer.lua` - macOS installer version
- `/installers/linux/PacketSanitizer.lua` - Linux installer version
- `/installers/windows/PacketSanitizer.lua` - Windows installer version

## Testing Checklist

- [x] Plugin loads without errors
- [x] Detects packets when capture file is open
- [x] Shows file dialog when no packets are loaded
- [x] Generates correct timestamp format for temp files
- [x] All three sanitization modes work correctly
- [x] Success message displays source information correctly
- [x] Cross-platform path handling works
- [x] Backward compatibility maintained

## Version Information

- **Plugin Version**: 0.1.1 (unchanged, as this is an enhancement to existing functionality)
- **Wireshark Requirement**: 3.0+
- **Python Requirement**: 3.6+
- **Scapy Requirement**: Latest stable version

## Notes for Future Versions

When updating to v0.2.0, consider:
1. Making this a major feature highlight
2. Adding support for filtered packet export
3. Implementing full `dumpcap` integration for live capture export
4. Adding configuration options for buffer detection behavior
5. Updating version number and release notes accordingly
