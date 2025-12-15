-- PacketSanitizer Wireshark Lua Plugin
-- Version: 0.2.0
--
-- A Wireshark plugin to sanitize PCAP/PCAPNG files for safe sharing
-- Replaces IPs, MACs, removes payloads, and voids sensitive data

-- Check if GUI is enabled (required for menu)
if not gui_enabled() then return end

local plugin_name = "PacketSanitizer"
local plugin_version = "0.2.0"

-- Register plugin information for Wireshark's About - Plugins list
-- Wireshark automatically detects plugins in the plugins directory
-- The plugin name and version are extracted from comments and variables
-- Use set_plugin_info if available for better version display
if set_plugin_info then
    set_plugin_info({
        version = plugin_version,
        author = "Walter Hofstetter",
        description = "Sanitize PCAP/PCAPNG files for safe sharing - anonymizes IPs, MACs, and sanitizes payloads"
    })
end

-- Helper function to detect platform
local function is_windows()
    return package.config:sub(1,1) == "\\"
end

-- Helper function to detect macOS
local function is_macos()
    if is_windows() then
        return false
    end
    -- Check for macOS-specific commands or paths
    local handle = io.popen("uname -s 2>/dev/null")
    if handle then
        local result = handle:read("*a")
        handle:close()
        if result and result:match("Darwin") then
            return true
        end
    end
    return false
end

-- Helper function to show messages
local function show_message(title, message)
    -- Use TextWindow.new() which is the standard Wireshark Lua API
    local tw = TextWindow.new(title)
    tw:set(message)
    tw:set_atclose(function() end)  -- Keep window open until user closes it
end

-- Helper function to get timestamp-formatted filename
local function get_timestamp_filename()
    -- Get current date/time and format as Capture_YYYYMMDD_HHMMSS
    return "Capture_" .. os.date("%Y%m%d_%H%M%S")
end

-- Helper function to get temp directory (platform-specific)
local function get_temp_dir()
    if is_windows() then
        return os.getenv("TEMP") or os.getenv("TMP") or "C:\\Windows\\Temp"
    else
        return os.getenv("TMPDIR") or os.getenv("TMP") or "/tmp"
    end
end

-- Get the currently open capture file (most reliable method)
-- Returns the file path if a capture is open, nil otherwise
local function get_currently_open_capture_file()
    -- Try multiple methods to get the open file path
    
    -- Method 1: CaptureInfo.file (most direct)
    if CaptureInfo and CaptureInfo.file then
        local file = tostring(CaptureInfo.file)
        if file and file ~= "" then
            return file
        end
    end
    
    -- Method 2: get_capture_file() - official API
    local ok1, result1 = pcall(function()
        return get_capture_file()
    end)
    if ok1 and result1 then
        local file = tostring(result1)
        if file and file ~= "" then
            return file
        end
    end
    
    -- Method 3: Try get_window_title() for window info
    local ok3, title = pcall(function()
        if get_window_title then
            return get_window_title()
        end
        return nil
    end)
    if ok3 and title then
        -- Window title often contains filename, try to extract it
        -- Format is usually "filename - Wireshark"
        local filename = tostring(title):match("^(.+)%s*%-")
        if filename and filename ~= "" then
            -- Check if this looks like a path
            if filename:match("/") or filename:match("\\") then
                return filename
            end
        end
    end
    
    -- Method 4: Check running_mode
    local ok2, running = pcall(function()
        return running_mode()
    end)
    if ok2 and running then
        -- Running mode indicates packets are loaded
        return "__PACKETS_LOADED__"
    end
    
    return nil
end

-- Helper function to check if packets are available in buffer
-- Returns true if packets are loaded, false otherwise
local function has_packets_in_buffer()
    local file_path = get_currently_open_capture_file()
    return file_path ~= nil
end

-- Export displayed packets via a tap listener to a temporary pcapng
-- Respects the current display filter. Works in menu callback context.
-- Returns temp file path on success, or nil on failure
local function export_displayed_packets_via_tap()
    -- Build temp path
    local temp_dir = get_temp_dir()
    local temp_filename = get_timestamp_filename() .. ".pcapng"
    local temp_path = is_windows() and (temp_dir .. "\\" .. temp_filename) or (temp_dir .. "/" .. temp_filename)

    -- Get current display filter (optional)
    local filter = ""
    if get_filter then
        local ok, f = pcall(get_filter)
        if ok and f then filter = tostring(f) end
    end

    -- Create dumper (pcapng if supported)
    local ok_dumper, dumper = pcall(function()
        if wtap_pcapng_file_type_subtype then
            return Dumper.new(temp_path, wtap_pcapng_file_type_subtype())
        else
            return Dumper.new(temp_path)
        end
    end)
    if not ok_dumper or not dumper then
        return nil
    end

    local count = 0
    -- Create a tap on the current packet set
    local ok_tap, tap_or_err = pcall(function()
        if filter and filter ~= "" then
            return Listener.new("frame", filter)
        else
            return Listener.new("frame")
        end
    end)
    if not ok_tap or not tap_or_err then
        pcall(function() dumper:close() end)
        return nil
    end
    local tap = tap_or_err

    function tap.packet(pinfo, tvb)
        -- Dump currently dissected packet
        dumper:dump_current()
        count = count + 1
    end

    function tap.draw()
        -- Close dumper when retap completes
        pcall(function() dumper:close() end)
    end

    -- Run taps over displayed packets
    if retap_packets then
        retap_packets()
    else
        -- Older Wireshark fallback
        if redissect_packets then redissect_packets() end
    end

    -- Remove tap to avoid leaks
    pcall(function() tap:remove() end)

    if count > 0 then
        -- Verify file exists
        local f = io.open(temp_path, "r")
        if f then f:close() return temp_path end
    end
    -- Clean up on failure
    pcall(function() os.remove(temp_path) end)
    return nil
end

-- Function to show file dialog (platform-specific)
local function show_file_dialog()
    local file_path = nil
    
    if is_windows() then
        -- Windows: Use PowerShell file dialog
        -- Create a temporary PowerShell script file to avoid escaping issues
        local tmp_dir = os.getenv("TEMP") or os.getenv("TMP") or "C:\\Windows\\Temp"
        local tmp_script = tmp_dir .. "\\packetsanitizer_" .. os.time() .. ".ps1"
        
        -- PowerShell script content
        local ps_content = 'Add-Type -AssemblyName System.Windows.Forms\n' ..
                          '$dialog = New-Object System.Windows.Forms.OpenFileDialog\n' ..
                          '$dialog.Filter = "PCAP files (*.pcap, *.pcapng)|*.pcap;*.pcapng|All files (*.*)|*.*"\n' ..
                          '$dialog.Title = "Select PCAP/PCAPNG file to sanitize"\n' ..
                          'if ($dialog.ShowDialog() -eq "OK") {\n' ..
                          '    Write-Output $dialog.FileName\n' ..
                          '}\n'
        
        -- Write PowerShell script to temp file
        local script_file = io.open(tmp_script, "w")
        if script_file then
            script_file:write(ps_content)
            script_file:close()
            
            -- Execute PowerShell script
            local ps_cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -File "' .. tmp_script .. '" 2>&1'
            local handle = io.popen(ps_cmd)
            if handle then
                local raw_result = handle:read("*a")
                handle:close()
                
                -- Clean up temp file
                os.remove(tmp_script)
                
                -- Process the result
                if raw_result and raw_result ~= "" then
                    local result = raw_result:gsub("\n", ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
                    -- Check if it's a valid Windows path (drive letter or UNC path)
                    if result:match("^[A-Za-z]:") or result:match("^\\\\") then
                        -- Additional validation: make sure it's not an error message
                        local lower_result = string.lower(result)
                        if not lower_result:match("error") and 
                           not lower_result:match("exception") and
                           not lower_result:match("cannot") and
                           not lower_result:match("not found") then
                            file_path = result
                        end
                    end
                end
            else
                -- Clean up temp file even if handle failed
                os.remove(tmp_script)
            end
        end
    elseif is_macos() then
        -- macOS: Use osascript
        local tmp_dir = os.getenv("TMPDIR") or os.getenv("TMP") or "/tmp"
        local tmp_script = tmp_dir .. "/packetsanitizer_" .. os.time() .. ".scpt"
        
        -- Write AppleScript to temp file
        local script_content = 'try\n' ..
                              '  set theFile to choose file with prompt "Select PCAP/PCAPNG file to sanitize" of type {"pcap", "pcapng"} default location (path to desktop folder)\n' ..
                              '  return POSIX path of theFile\n' ..
                              'on error\n' ..
                              '  return ""\n' ..
                              'end try\n'
        
        local script_file = io.open(tmp_script, "w")
        if script_file then
            script_file:write(script_content)
            script_file:close()
            
            -- Execute osascript
            local file_dialog_cmd = 'osascript "' .. tmp_script .. '" 2>&1'
            local handle = io.popen(file_dialog_cmd)
            local raw_result = nil
            
            if handle then
                raw_result = handle:read("*a")
                handle:close()
            end
            
            -- Clean up temp file
            os.remove(tmp_script)
            
            -- Process the result
            if raw_result and raw_result ~= "" then
                local result = raw_result:gsub("\n", ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
                if result:match("^/") then  -- POSIX path
                    local lower_result = string.lower(result)
                    if not lower_result:match("error") and 
                       not lower_result:match("cancelled") and 
                       not lower_result:match("timeout") and
                       not lower_result:match("user cancelled") and
                       not lower_result:match("execution error") then
                        file_path = result
                    end
                end
            end
        end
    else
        -- Linux: Try zenity, kdialog, or yad
        local dialog_cmd = nil
        local dialog_test = nil
        
        -- Try zenity (GNOME)
        dialog_test = io.popen("which zenity 2>/dev/null")
        if dialog_test then
            local zenity_path = dialog_test:read("*a")
            dialog_test:close()
            if zenity_path and zenity_path ~= "" then
                zenity_path = zenity_path:gsub("\n", ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
                -- zenity returns file path on selection, empty string on cancel
                -- Use --separator to ensure single line output
                dialog_cmd = zenity_path .. " --file-selection --title='Select PCAP/PCAPNG file to sanitize' --file-filter='PCAP files | *.pcap *.pcapng' --file-filter='All files | *.*' 2>/dev/null"
            end
        end
        
        -- Try kdialog (KDE) if zenity not found
        if not dialog_cmd then
            dialog_test = io.popen("which kdialog 2>/dev/null")
            if dialog_test then
                local kdialog_path = dialog_test:read("*a")
                dialog_test:close()
                if kdialog_path and kdialog_path ~= "" then
                    kdialog_path = kdialog_path:gsub("\n", ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
                    -- kdialog returns file path on selection, empty string on cancel
                    dialog_cmd = kdialog_path .. " --getopenfilename $HOME 'PCAP files (*.pcap *.pcapng)' 2>/dev/null"
                end
            end
        end
        
        -- Try yad if neither zenity nor kdialog found
        if not dialog_cmd then
            dialog_test = io.popen("which yad 2>/dev/null")
            if dialog_test then
                local yad_path = dialog_test:read("*a")
                dialog_test:close()
                if yad_path and yad_path ~= "" then
                    yad_path = yad_path:gsub("\n", ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
                    -- yad returns file path on selection, empty string on cancel
                    dialog_cmd = yad_path .. " --file --title='Select PCAP/PCAPNG file to sanitize' --file-filter='PCAP files | *.pcap *.pcapng' 2>/dev/null"
                end
            end
        end
        
        -- Execute the dialog command if found
        if dialog_cmd then
            local handle = io.popen(dialog_cmd)
            if handle then
                local raw_result = handle:read("*a")
                handle:close()
                
                if raw_result and raw_result ~= "" then
                    -- Clean up the result - remove all whitespace and newlines
                    local result = raw_result:gsub("\n", ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
                    
                    -- Check if it's a valid absolute path (starts with /)
                    -- zenity/kdialog/yad return empty string on cancel, or a path on selection
                    if result ~= "" and result:match("^/") then
                        -- Additional validation: make sure it's not an error message
                        local lower_result = string.lower(result)
                        if not lower_result:match("error") and 
                           not lower_result:match("not found") and
                           not lower_result:match("cancelled") and
                           not lower_result:match("timeout") then
                            file_path = result
                        end
                    end
                end
            end
        end
    end
    
    return file_path
end

-- Function to sanitize the current capture file
-- mode: "all_payload", "cleartext_payload", or "payload_and_addresses"
local function sanitize_capture(mode)
    local file_path = nil
    local is_temp_file = false
    
-- Step 1: Try to export displayed packets via tap (respects filter)
local tmp_from_tap = export_displayed_packets_via_tap()
if tmp_from_tap then
    file_path = tmp_from_tap
    is_temp_file = true
end

-- Step 2: If tap export failed, try to get the currently open capture file
if not file_path then
    file_path = get_currently_open_capture_file()
end

-- Step 3: If still no file, show dialog
if not file_path or file_path == "" or file_path == "__WIRESHARK_BUFFER__" or file_path == "__PACKETS_LOADED__" then
    file_path = show_file_dialog()
        
        -- If file dialog was cancelled or failed, show instructions
        if not file_path or file_path == "" then
            local debug_msg = "File selection dialog was cancelled or unavailable.\n\n"
            
            if is_windows() then
                debug_msg = debug_msg .. "You can sanitize files using the command line:\n\n" ..
                    "python \"%APPDATA%\\Wireshark\\plugins\\PacketSanitizer\\sanitize_packets.py\" ^\n" ..
                    "  <mode> <input_file> <output_file>\n\n" ..
                    "Example:\n" ..
                    "python \"%APPDATA%\\Wireshark\\plugins\\PacketSanitizer\\sanitize_packets.py\" ^\n" ..
                    "  payload_and_addresses C:\\Users\\YourName\\Downloads\\capture.pcap C:\\Users\\YourName\\Downloads\\capture_sanitized.pcap"
            else
                -- Check if dialog tools are available
                local has_dialog = false
                local dialog_name = ""
                local test_handle = io.popen("which zenity kdialog yad 2>/dev/null | head -1")
                if test_handle then
                    local dialog_tool = test_handle:read("*a")
                    test_handle:close()
                    if dialog_tool and dialog_tool ~= "" then
                        has_dialog = true
                        if dialog_tool:match("zenity") then
                            dialog_name = "zenity"
                        elseif dialog_tool:match("kdialog") then
                            dialog_name = "kdialog"
                        elseif dialog_tool:match("yad") then
                            dialog_name = "yad"
                        end
                    end
                end
                
                if not has_dialog then
                    debug_msg = debug_msg .. "No file dialog tool found (zenity/kdialog/yad).\n" ..
                        "Install one for GUI file selection:\n" ..
                        "  sudo apt install zenity    # Debian/Ubuntu\n" ..
                        "  sudo dnf install zenity    # Fedora\n\n"
                end
                
                debug_msg = debug_msg .. "You can sanitize files using the command line:\n\n" ..
                    "python3 ~/.local/lib/wireshark/plugins/PacketSanitizer/sanitize_packets.py \\\n" ..
                    "  <mode> <input_file> <output_file>\n\n" ..
                    "Example:\n" ..
                    "python3 ~/.local/lib/wireshark/plugins/PacketSanitizer/sanitize_packets.py \\\n" ..
                    "  payload_and_addresses ~/Downloads/capture.pcap ~/Downloads/capture_sanitized.pcap"
            end
            
            show_message("PacketSanitizer - File Selection", debug_msg)
            return
        end
    end
    
    -- Verify the file exists and is readable
    local file = io.open(file_path, "r")
    if not file then
        show_message("PacketSanitizer", 
            "Error: Cannot access file\n\n" ..
            "File path: " .. file_path .. "\n\n" ..
            "The file may not exist or you may not have permission to read it.")
        return
    end
    file:close()
    
    -- Check if Python script exists
    -- Get the directory where this Lua script is located
    local script_source = debug.getinfo(1, "S").source:match("@(.*)")
    local script_dir = script_source
    
    -- Extract directory path (remove filename)
    if is_windows() then
        -- Windows: remove filename and normalize to backslashes
        script_dir = script_dir:gsub("/", "\\")
        script_dir = script_dir:match("^(.*\\)") or script_dir
        if not script_dir:match("\\$") then
            script_dir = script_dir .. "\\"
        end
    else
        -- Unix-like: remove filename and normalize to forward slashes
        script_dir = script_dir:gsub("\\", "/")
        script_dir = script_dir:match("^(.*/)") or script_dir
        if not script_dir:match("/$") then
            script_dir = script_dir .. "/"
        end
    end
    local python_script = script_dir .. "sanitize_packets.py"
    
    -- Check if file exists (Lua file check)
    local file = io.open(python_script, "r")
    if not file then
        show_message("PacketSanitizer", 
            "Error: Python script not found at: " .. python_script .. 
            "\n\nPlease ensure sanitize_packets.py is in the same directory as this Lua script.")
        return
    end
    file:close()
    
    -- Generate output filename based on mode
    local suffix = "_sanitized"
    if mode == "all_payload" then
        suffix = "_sanitized_payload"
    elseif mode == "cleartext_payload" then
        suffix = "_sanitized_cleartext"
    elseif mode == "payload_and_addresses" then
        suffix = "_sanitized_full"
    end
    local output_file = file_path:gsub("%.pcapng?$", "") .. suffix .. ".pcap"
    
    -- Find the correct Python 3 executable (platform-specific)
    local python_cmd = nil
    
    if is_windows() then
        -- Windows: Try 'where python' or 'where python3'
        local python_test = io.popen('where python 2>nul')
        if python_test then
            local python_path = python_test:read("*a")
            python_test:close()
            if python_path and python_path ~= "" then
                python_path = python_path:gsub("\n", ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
                -- Verify it can import scapy
                local scapy_test = io.popen('"' .. python_path .. '" -c "import scapy" 2>&1')
                if scapy_test then
                    local scapy_result = scapy_test:read("*a")
                    scapy_test:close()
                    if not scapy_result:match("ModuleNotFoundError") and not scapy_result:match("ImportError") then
                        python_cmd = python_path
                    end
                end
            end
        end
        
        -- Try python3 on Windows
        if not python_cmd then
            python_test = io.popen('where python3 2>nul')
            if python_test then
                local python_path = python_test:read("*a")
                python_test:close()
                if python_path and python_path ~= "" then
                    python_path = python_path:gsub("\n", ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
                    local scapy_test = io.popen('"' .. python_path .. '" -c "import scapy" 2>&1')
                    if scapy_test then
                        local scapy_result = scapy_test:read("*a")
                        scapy_test:close()
                        if not scapy_result:match("ModuleNotFoundError") and not scapy_result:match("ImportError") then
                            python_cmd = python_path
                        end
                    end
                end
            end
        end
        
        -- Try common Windows Python locations
        if not python_cmd then
            local common_paths = {
                os.getenv("LOCALAPPDATA") .. "\\Programs\\Python\\Python3*\\python.exe",
                os.getenv("ProgramFiles") .. "\\Python3*\\python.exe",
                "C:\\Python3*\\python.exe",
                "C:\\Python*\\python.exe"
            }
            for _, path_pattern in ipairs(common_paths) do
                -- Note: Lua doesn't support glob, so we check specific versions
                for version = 12, 6, -1 do
                    local path = path_pattern:gsub("%*", tostring(version))
                    local test_file = io.open(path, "r")
                    if test_file then
                        test_file:close()
                        local scapy_test = io.popen('"' .. path .. '" -c "import scapy" 2>&1')
                        if scapy_test then
                            local scapy_result = scapy_test:read("*a")
                            scapy_test:close()
                            if not scapy_result:match("ModuleNotFoundError") and not scapy_result:match("ImportError") then
                                python_cmd = path
                                break
                            end
                        end
                    end
                end
                if python_cmd then break end
            end
        end
        
        -- Fallback to python on Windows
        if not python_cmd then
            python_cmd = "python"
        end
    else
        -- Unix-like (macOS/Linux): Try 'which python3'
        local python_test = io.popen('which python3 2>/dev/null')
        if python_test then
            local python_path = python_test:read("*a")
            python_test:close()
            if python_path and python_path ~= "" then
                python_path = python_path:gsub("\n", ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
                -- Verify it can import scapy
                local scapy_test = io.popen('"' .. python_path .. '" -c "import scapy" 2>&1')
                if scapy_test then
                    local scapy_result = scapy_test:read("*a")
                    scapy_test:close()
                    if not scapy_result:match("ModuleNotFoundError") and not scapy_result:match("ImportError") then
                        python_cmd = python_path
                    end
                end
            end
        end
        
        -- Try common Unix Python locations
        if not python_cmd then
            local common_paths = {
                "/usr/local/bin/python3",
                "/opt/homebrew/bin/python3",
                "/usr/bin/python3"
            }
            for _, path in ipairs(common_paths) do
                local test_file = io.open(path, "r")
                if test_file then
                    test_file:close()
                    local scapy_test = io.popen('"' .. path .. '" -c "import scapy" 2>&1')
                    if scapy_test then
                        local scapy_result = scapy_test:read("*a")
                        scapy_test:close()
                        if not scapy_result:match("ModuleNotFoundError") and not scapy_result:match("ImportError") then
                            python_cmd = path
                            break
                        end
                    end
                end
            end
        end
        
        -- Fallback to python3 on Unix
        if not python_cmd then
            python_cmd = "python3"
        end
    end
    
    -- Call Python script and capture output (platform-specific command construction)
    local command = nil
    local output = ""
    local exit_code = nil
    
    if is_windows() then
        -- Windows: Create a temporary batch file to avoid command parsing issues
        local tmp_dir = os.getenv("TEMP") or os.getenv("TMP") or "C:\\Windows\\Temp"
        local tmp_bat = tmp_dir .. "\\packetsanitizer_" .. os.time() .. ".bat"
        
        -- Create batch file content
        local bat_content = string.format('@echo off\n"%s" "%s" %s "%s" "%s" 2>&1\n', 
            python_cmd:gsub('"', '""'),  -- Escape quotes in Python path
            python_script:gsub('"', '""'),  -- Escape quotes in script path
            mode,
            file_path:gsub('"', '""'),  -- Escape quotes in file paths
            output_file:gsub('"', '""'))
        
        -- Write batch file
        local bat_file = io.open(tmp_bat, "w")
        if bat_file then
            bat_file:write(bat_content)
            bat_file:close()
            
            -- Execute batch file
            command = '"' .. tmp_bat .. '"'
            local handle = io.popen(command)
            if handle then
                output = handle:read("*a")
                exit_code = handle:close()
            end
            
            -- Clean up batch file
            os.remove(tmp_bat)
        else
            -- Fallback: Try direct command if batch file creation fails
            command = string.format('"%s" "%s" %s "%s" "%s"', 
                python_cmd, python_script, mode, file_path, output_file)
            local handle = io.popen(command .. ' 2>&1')
            if handle then
                output = handle:read("*a")
                exit_code = handle:close()
            end
        end
    else
        -- Unix-like: Standard shell syntax
        command = string.format('"%s" "%s" "%s" "%s" "%s" 2>&1', 
            python_cmd, python_script, mode, file_path, output_file)
        local handle = io.popen(command)
        if handle then
            output = handle:read("*a")
            exit_code = handle:close()
        end
    end
    
    -- Check if output file was created (more reliable than exit code)
    local output_exists = false
    local output_file_handle = io.open(output_file, "r")
    if output_file_handle then
        output_exists = true
        output_file_handle:close()
    end
    
    if exit_code == 0 or output_exists then
        -- Show success message with option to open the file
        local tw = TextWindow.new("PacketSanitizer - Success")
        local mode_description = ""
        if mode == "all_payload" then
            mode_description = "All Payloads"
        elseif mode == "cleartext_payload" then
            mode_description = "Clear Text Payloads Only"
        elseif mode == "payload_and_addresses" then
            mode_description = "Payloads and IP/MAC Addresses"
        end
        
        -- Build success message with packet detection info
        local success_msg = "Success! Sanitization complete.\n\n" ..
            "Mode: " .. mode_description .. "\n"
        
        -- Add info about packet detection
        if is_temp_file then
            success_msg = success_msg .. "Source: Packets from buffer (" .. get_timestamp_filename() .. ".pcapng)\n"
        else
            success_msg = success_msg .. "Source: " .. file_path .. "\n"
        end
        
        success_msg = success_msg .. "Output: " .. output_file .. "\n\n" ..
            "The sanitized file has been created and can be safely shared.\n\n" ..
            "Click 'Open File' below to load it in Wireshark, or close this window."
        
        tw:set(success_msg)
        
        -- Add button to open the sanitized file
        tw:add_button("Open File", function()
            -- Try to open the file in Wireshark (platform-specific)
            if is_windows() then
                -- Windows: Use start command
                os.execute('start "" "' .. output_file .. '"')
            elseif is_macos() then
                -- macOS: Use 'open' command
                local wireshark_cmd = 'open -a Wireshark "' .. output_file .. '" 2>/dev/null || open "' .. output_file .. '"'
                os.execute(wireshark_cmd)
            else
                -- Linux: Try xdg-open (standard), or try to find Wireshark executable
                local open_cmd = 'xdg-open "' .. output_file .. '" 2>/dev/null'
                -- Try to find wireshark executable and open with it
                local ws_test = io.popen("which wireshark 2>/dev/null")
                if ws_test then
                    local ws_path = ws_test:read("*a")
                    ws_test:close()
                    if ws_path and ws_path ~= "" then
                        ws_path = ws_path:gsub("\n", ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
                        open_cmd = '"' .. ws_path .. '" "' .. output_file .. '" 2>/dev/null &'
                    end
                end
                os.execute(open_cmd)
            end
            tw:close()
        end)
        
        -- Keep window open
        tw:set_atclose(function() end)
    else
        -- Show detailed error information
        local error_msg = "Error: Sanitization failed.\n\n"
        
        if output and output ~= "" then
            -- Clean up output for display
            local clean_output = output:gsub("\n", "\\n"):gsub("\r", "\\r"):sub(1, 500)
            error_msg = error_msg .. "Python script output:\n" .. clean_output .. "\n\n"
        end
        
        error_msg = error_msg .. "Command executed:\n" .. command .. "\n\n" ..
            "Please check:\n" ..
            "1. Python 3 is installed (python3 --version)\n" ..
            "2. Scapy library is installed (pip3 install scapy)\n" ..
            "3. The Python script is accessible: " .. python_script .. "\n" ..
            "4. You have read permission for: " .. file_path
        
        show_message("PacketSanitizer - Error", error_msg)
    end
end

-- Register main menu item with submenus
register_menu("PacketSanitizer/Sanitize All Payload", function() sanitize_capture("all_payload") end, MENU_TOOLS_UNSORTED)
register_menu("PacketSanitizer/Sanitize Clear Text Payload", function() sanitize_capture("cleartext_payload") end, MENU_TOOLS_UNSORTED)
register_menu("PacketSanitizer/Sanitize Payload and IP & MAC Addresses", function() sanitize_capture("payload_and_addresses") end, MENU_TOOLS_UNSORTED)

