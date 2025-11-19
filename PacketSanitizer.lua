-- PacketSanitizer Wireshark Lua Plugin
-- Version: 0.1.0
--
-- A Wireshark plugin to sanitize PCAP/PCAPNG files for safe sharing
-- Replaces IPs, MACs, removes payloads, and voids sensitive data

-- Check if GUI is enabled (required for menu)
if not gui_enabled() then return end

local plugin_name = "PacketSanitizer"
local plugin_version = "0.1.0"

-- Helper function to show messages
local function show_message(title, message)
    -- Use TextWindow.new() which is the standard Wireshark Lua API
    local tw = TextWindow.new(title)
    tw:set(message)
    tw:set_atclose(function() end)  -- Keep window open until user closes it
end

-- Function to sanitize the current capture file
local function sanitize_capture()
    local file_path = nil
    
    -- Try to get file path from CaptureInfo (may not be available in menu context)
    if CaptureInfo and CaptureInfo.file then
        file_path = tostring(CaptureInfo.file)
    end
    
    -- If no file path from CaptureInfo, use macOS file dialog
    if not file_path or file_path == "" then
        -- Use osascript with a simpler approach (no System Events needed)
        -- Create a temporary AppleScript file
        local tmp_dir = os.getenv("TMPDIR") or os.getenv("TMP") or "/tmp"
        local tmp_script = tmp_dir .. "/packetsanitizer_" .. os.time() .. ".scpt"
        local osascript_debug = nil  -- Store debug info outside the block
        
        -- Write AppleScript to temp file (simpler version without System Events)
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
                osascript_debug = raw_result  -- Store for debugging
                handle:close()
            end
            
            -- Clean up temp file
            os.remove(tmp_script)
            
            -- Process the result
            if raw_result and raw_result ~= "" then
                -- Clean up the result - remove whitespace
                local result = raw_result:gsub("\n", ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
                
                -- Check if it's a valid POSIX path (starts with /)
                if result:match("^/") then
                    -- Check it's not an error message (case-insensitive)
                    local lower_result = string.lower(result)
                    if not lower_result:match("error") and 
                       not lower_result:match("cancelled") and 
                       not lower_result:match("timeout") and
                       not lower_result:match("user cancelled") and
                       not lower_result:match("execution error") and
                       not lower_result:match("system events") then
                        file_path = result
                    end
                end
            end
        end
        
        -- If file dialog was cancelled or failed, show instructions with debug info
        if not file_path or file_path == "" then
            local debug_msg = "File selection dialog result couldn't be parsed.\n\n"
            
            -- Show what osascript actually returned
            if osascript_debug and osascript_debug ~= "" then
                local clean_debug = osascript_debug:gsub("\n", "\\n"):gsub("\r", "\\r"):sub(1, 200)
                debug_msg = debug_msg .. "Debug info - osascript returned:\n" .. clean_debug .. "\n\n"
            else
                debug_msg = debug_msg .. "Debug info - osascript returned nothing (empty or cancelled).\n\n"
            end
            
            debug_msg = debug_msg .. "You can sanitize files using the command line:\n\n" ..
                "python3 ~/.local/lib/wireshark/plugins/PacketSanitizer/sanitize_packets.py \\\n" ..
                "  <input_file> <output_file>\n\n" ..
                "Example:\n" ..
                "python3 ~/.local/lib/wireshark/plugins/PacketSanitizer/sanitize_packets.py \\\n" ..
                "  ~/Downloads/capture.pcap ~/Downloads/capture_sanitized.pcap"
            
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
    local script_dir = debug.getinfo(1, "S").source:match("@(.*/)")
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
    
    -- Generate output filename
    local output_file = file_path:gsub("%.pcapng?$", "") .. "_sanitized.pcap"
    
    -- Find the correct Python 3 executable
    -- Try multiple methods to find python3 with scapy
    local python_cmd = nil
    
    -- Method 1: Try to find python3 in PATH
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
    
    -- Method 2: Try common Python locations
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
    
    -- Fallback to python3 if nothing found
    if not python_cmd then
        python_cmd = "python3"
    end
    
    -- Call Python script and capture output
    local command = string.format('"%s" "%s" "%s" "%s" 2>&1', python_cmd, python_script, file_path, output_file)
    
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
        local success_msg = "Success! Sanitization complete.\n\n" ..
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

-- Register menu item in Tools menu
register_menu("Sanitize PCAP(NG)", sanitize_capture, MENU_TOOLS_UNSORTED)

