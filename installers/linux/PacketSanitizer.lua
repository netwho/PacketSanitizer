-- PacketSanitizer Wireshark Lua Plugin
-- Version: 0.1.0
--
-- A Wireshark plugin to sanitize PCAP/PCAPNG files for safe sharing
-- Replaces IPs, MACs, removes payloads, and voids sensitive data

-- Check if GUI is enabled (required for menu)
if not gui_enabled() then return end

local plugin_name = "PacketSanitizer"
local plugin_version = "0.1.0"

-- Register plugin information for Wireshark's About - Plugins list
-- Wireshark automatically detects plugins in the plugins directory
-- The plugin name and version are extracted from comments and variables
-- Use set_plugin_info if available for better version display
if set_plugin_info then
    set_plugin_info({
        version = plugin_version,
        author = "PacketSanitizer Contributors",
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

-- Function to show file dialog (platform-specific)
local function show_file_dialog()
    local file_path = nil
    
    if is_windows() then
        -- Windows: Use PowerShell file dialog
        local ps_script = '[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null; $dialog = New-Object System.Windows.Forms.OpenFileDialog; $dialog.Filter = "PCAP files (*.pcap, *.pcapng)|*.pcap;*.pcapng|All files (*.*)|*.*"; $dialog.Title = "Select PCAP/PCAPNG file to sanitize"; if ($dialog.ShowDialog() -eq "OK") { Write-Output $dialog.FileName }'
        local ps_cmd = 'powershell -NoProfile -Command "' .. ps_script:gsub('"', '\\"') .. '"'
        local handle = io.popen(ps_cmd)
        if handle then
            local result = handle:read("*a")
            handle:close()
            if result and result ~= "" then
                result = result:gsub("\n", ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
                if result:match("^[A-Za-z]:") or result:match("^\\\\") then  -- Windows path
                    file_path = result
                end
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
    
    -- Try to get file path from CaptureInfo (may not be available in menu context)
    if CaptureInfo and CaptureInfo.file then
        file_path = tostring(CaptureInfo.file)
    end
    
    -- If no file path from CaptureInfo, use platform-specific file dialog
    if not file_path or file_path == "" then
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
    
    -- Call Python script and capture output
    local command = string.format('"%s" "%s" "%s" "%s" "%s" 2>&1', python_cmd, python_script, mode, file_path, output_file)
    
    -- Execute command and capture output
    local handle = io.popen(command)
    local output = ""
    local exit_code = nil
    
    if handle then
        output = handle:read("*a")
        exit_code = handle:close()  -- Returns exit code on success
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
        local success_msg = "Success! Sanitization complete.\n\n" ..
            "Mode: " .. mode_description .. "\n" ..
            "Original file: " .. file_path .. "\n" ..
            "Sanitized file: " .. output_file .. "\n\n" ..
            "The sanitized file has been created and can be safely shared.\n\n" ..
            "Click 'Open File' below to load it in Wireshark, or close this window."
        
        tw:set(success_msg)
        
        -- Add button to open the sanitized file
        tw:add_button("Open File", function()
            -- Try to open the file in Wireshark
            -- On macOS, use 'open' command which will use the default app for .pcap files
            -- This should open in Wireshark if it's the default app
            local open_cmd = nil
            if package.config:sub(1,1) == "/" then  -- Unix-like (macOS/Linux)
                -- Try to open with Wireshark directly first
                local wireshark_cmd = 'open -a Wireshark "' .. output_file .. '" 2>/dev/null || open "' .. output_file .. '"'
                os.execute(wireshark_cmd)
            else
                -- Windows
                os.execute('start "" "' .. output_file .. '"')
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

