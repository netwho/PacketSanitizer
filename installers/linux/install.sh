#!/usr/bin/env bash
#
# PacketSanitizer - Linux Installation Script
# Installs the PacketSanitizer plugin with prerequisite checks
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}PacketSanitizer - Linux Installation${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Detect package manager
echo -e "${BLUE}Detecting system configuration...${NC}"
echo ""

PKG_MANAGER=""
INSTALL_CMD=""
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt"
    INSTALL_CMD="sudo apt install"
    echo -e "${GREEN}✓${NC} Package manager: apt (Debian/Ubuntu)"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
    INSTALL_CMD="sudo dnf install"
    echo -e "${GREEN}✓${NC} Package manager: dnf (Fedora/RHEL 8+)"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
    INSTALL_CMD="sudo yum install"
    echo -e "${GREEN}✓${NC} Package manager: yum (RHEL/CentOS)"
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
    INSTALL_CMD="sudo pacman -S"
    echo -e "${GREEN}✓${NC} Package manager: pacman (Arch Linux)"
elif command -v zypper &> /dev/null; then
    PKG_MANAGER="zypper"
    INSTALL_CMD="sudo zypper install"
    echo -e "${GREEN}✓${NC} Package manager: zypper (openSUSE)"
else
    echo -e "${YELLOW}⚠${NC}  Package manager not detected (manual installation required)"
    PKG_MANAGER="unknown"
fi

# Prerequisites check
echo ""
echo -e "${BLUE}Checking prerequisites...${NC}"
echo ""

PREREQ_FAILED=false

# Check for Wireshark
echo -e "${YELLOW}→${NC} Checking for Wireshark..."
if command -v wireshark &> /dev/null; then
    WS_VERSION=$(wireshark --version 2>/dev/null | head -n1 | awk '{print $2}' || echo "unknown")
    echo -e "${GREEN}✓${NC} Wireshark found (version: $WS_VERSION)"
    
    # Check version >= 3.0
    if [[ "$WS_VERSION" != "unknown" ]]; then
        MAJOR_VERSION=$(echo "$WS_VERSION" | cut -d. -f1)
        if [[ "$MAJOR_VERSION" -lt 3 ]]; then
            echo -e "${YELLOW}⚠${NC}  Warning: Wireshark 3.0+ recommended (found $WS_VERSION)"
        fi
    fi
elif dpkg -l | grep -q wireshark 2>/dev/null || rpm -qa | grep -q wireshark 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Wireshark package installed"
else
    echo -e "${RED}✗${NC} Wireshark not found"
    case "$PKG_MANAGER" in
        apt) echo -e "   Install with: sudo apt install wireshark" ;;
        dnf) echo -e "   Install with: sudo dnf install wireshark" ;;
        yum) echo -e "   Install with: sudo yum install wireshark" ;;
        pacman) echo -e "   Install with: sudo pacman -S wireshark-qt" ;;
        zypper) echo -e "   Install with: sudo zypper install wireshark" ;;
        *) echo -e "   Install from: https://www.wireshark.org/download.html" ;;
    esac
    PREREQ_FAILED=true
fi

# Check for Python 3
echo -e "${YELLOW}→${NC} Checking for Python 3..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
    
    if [[ "$PYTHON_MAJOR" -ge 3 ]] && [[ "$PYTHON_MINOR" -ge 6 ]]; then
        echo -e "${GREEN}✓${NC} Python 3 found (version: $PYTHON_VERSION)"
    else
        echo -e "${RED}✗${NC} Python 3.6+ required (found $PYTHON_VERSION)"
        case "$PKG_MANAGER" in
            apt) echo -e "   Install with: sudo apt install python3" ;;
            dnf) echo -e "   Install with: sudo dnf install python3" ;;
            yum) echo -e "   Install with: sudo yum install python3" ;;
            pacman) echo -e "   Install with: sudo pacman -S python" ;;
            zypper) echo -e "   Install with: sudo zypper install python3" ;;
            *) echo -e "   Install from: https://www.python.org/downloads/" ;;
        esac
        PREREQ_FAILED=true
    fi
else
    echo -e "${RED}✗${NC} Python 3 not found"
    case "$PKG_MANAGER" in
        apt) echo -e "   Install with: sudo apt install python3" ;;
        dnf) echo -e "   Install with: sudo dnf install python3" ;;
        yum) echo -e "   Install with: sudo yum install python3" ;;
        pacman) echo -e "   Install with: sudo pacman -S python" ;;
        zypper) echo -e "   Install with: sudo zypper install python3" ;;
        *) echo -e "   Install from: https://www.python.org/downloads/" ;;
    esac
    PREREQ_FAILED=true
fi

# Check for pip3
echo -e "${YELLOW}→${NC} Checking for pip3..."
if command -v pip3 &> /dev/null; then
    PIP_VERSION=$(pip3 --version 2>&1 | awk '{print $2}' || echo "found")
    echo -e "${GREEN}✓${NC} pip3 found (version: $PIP_VERSION)"
else
    echo -e "${YELLOW}⚠${NC}  pip3 not found (needed for Scapy installation)"
    case "$PKG_MANAGER" in
        apt) echo -e "   Install with: sudo apt install python3-pip" ;;
        dnf) echo -e "   Install with: sudo dnf install python3-pip" ;;
        yum) echo -e "   Install with: sudo yum install python3-pip" ;;
        pacman) echo -e "   Install with: sudo pacman -S python-pip" ;;
        zypper) echo -e "   Install with: sudo zypper install python3-pip" ;;
        *) echo -e "   Install pip from: https://pip.pypa.io/en/stable/installation/" ;;
    esac
fi

# Check for Scapy
echo -e "${YELLOW}→${NC} Checking for Scapy library..."
if python3 -c "import scapy" 2>/dev/null; then
    SCAPY_VERSION=$(python3 -c "import scapy; print(scapy.__version__)" 2>/dev/null || echo "found")
    echo -e "${GREEN}✓${NC} Scapy found (version: $SCAPY_VERSION)"
else
    echo -e "${YELLOW}✗${NC} Scapy not found"
    echo -e "   Install with: pip3 install scapy"
    echo -e "   Or using system package manager:"
    case "$PKG_MANAGER" in
        apt) echo -e "     sudo apt install python3-scapy" ;;
        dnf) echo -e "     sudo dnf install python3-scapy" ;;
        yum) echo -e "     sudo yum install python3-scapy" ;;
        pacman) echo -e "     sudo pacman -S python-scapy" ;;
        zypper) echo -e "     sudo zypper install python3-scapy" ;;
        *) echo -e "     Use: pip3 install scapy" ;;
    esac
    PREREQ_FAILED=true
fi

# Check Lua availability (usually bundled with Wireshark)
echo -e "${YELLOW}→${NC} Checking for Lua..."
if command -v lua &> /dev/null || command -v lua5.2 &> /dev/null || command -v lua5.3 &> /dev/null; then
    LUA_VERSION=$(lua -v 2>&1 | head -n1 || echo "found")
    echo -e "${GREEN}✓${NC} Lua found ($LUA_VERSION)"
else
    echo -e "${YELLOW}⚠${NC}  Lua command not found (but may be bundled with Wireshark)"
fi

# Exit if critical prerequisites failed
if [ "$PREREQ_FAILED" = true ]; then
    echo ""
    echo -e "${RED}✗ Installation cannot continue - prerequisites missing${NC}"
    echo -e "  Please install missing prerequisites and try again."
    exit 1
fi

echo ""
echo -e "${BLUE}Installing plugin...${NC}"
echo ""

# Determine plugin directory
PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins/PacketSanitizer"

echo -e "${GREEN}✓${NC} Plugin directory: $PLUGIN_DIR"

# Create plugin directory if it doesn't exist
if [ ! -d "$PLUGIN_DIR" ]; then
    echo -e "${YELLOW}→${NC} Creating plugin directory..."
    mkdir -p "$PLUGIN_DIR"
    echo -e "${GREEN}✓${NC} Directory created"
else
    echo -e "${GREEN}✓${NC} Directory exists"
fi

# Find and copy the plugin files
FILES_COPIED=0

# Copy PacketSanitizer.lua
if [ -f "$SCRIPT_DIR/PacketSanitizer.lua" ]; then
    echo -e "${YELLOW}→${NC} Installing PacketSanitizer.lua..."
    cp "$SCRIPT_DIR/PacketSanitizer.lua" "$PLUGIN_DIR/"
    chmod 644 "$PLUGIN_DIR/PacketSanitizer.lua"
    echo -e "${GREEN}✓${NC} PacketSanitizer.lua installed"
    FILES_COPIED=$((FILES_COPIED + 1))
elif [ -f "$SCRIPT_DIR/../../PacketSanitizer.lua" ]; then
    echo -e "${YELLOW}→${NC} Installing PacketSanitizer.lua from project root..."
    cp "$SCRIPT_DIR/../../PacketSanitizer.lua" "$PLUGIN_DIR/"
    chmod 644 "$PLUGIN_DIR/PacketSanitizer.lua"
    echo -e "${GREEN}✓${NC} PacketSanitizer.lua installed"
    FILES_COPIED=$((FILES_COPIED + 1))
else
    echo -e "${RED}✗${NC} PacketSanitizer.lua not found"
fi

# Copy sanitize_packets.py
if [ -f "$SCRIPT_DIR/sanitize_packets.py" ]; then
    echo -e "${YELLOW}→${NC} Installing sanitize_packets.py..."
    cp "$SCRIPT_DIR/sanitize_packets.py" "$PLUGIN_DIR/"
    chmod 755 "$PLUGIN_DIR/sanitize_packets.py"
    echo -e "${GREEN}✓${NC} sanitize_packets.py installed"
    FILES_COPIED=$((FILES_COPIED + 1))
elif [ -f "$SCRIPT_DIR/../../sanitize_packets.py" ]; then
    echo -e "${YELLOW}→${NC} Installing sanitize_packets.py from project root..."
    cp "$SCRIPT_DIR/../../sanitize_packets.py" "$PLUGIN_DIR/"
    chmod 755 "$PLUGIN_DIR/sanitize_packets.py"
    echo -e "${GREEN}✓${NC} sanitize_packets.py installed"
    FILES_COPIED=$((FILES_COPIED + 1))
else
    echo -e "${RED}✗${NC} sanitize_packets.py not found"
fi

# Verify installation
if [ "$FILES_COPIED" -lt 2 ]; then
    echo ""
    echo -e "${RED}✗ Installation incomplete - not all files were copied${NC}"
    exit 1
fi

# Verify Python can find Scapy from the plugin location
echo ""
echo -e "${BLUE}Verifying installation...${NC}"
echo ""

# Test that Python can import Scapy (using the same python3 that will be used)
if python3 -c "import scapy" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Scapy import test passed"
else
    echo -e "${YELLOW}⚠${NC}  Warning: Scapy import test failed"
    echo -e "   The plugin may not work correctly."
    echo -e "   Try: pip3 install scapy"
fi

# Final instructions
echo ""
echo -e "${BLUE}============================================${NC}"
echo -e "${GREEN}✓ Installation Complete!${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "  1. Restart Wireshark"
echo "  2. Go to: ${GREEN}Tools → PacketSanitizer${NC}"
echo "  3. Choose a sanitization mode:"
echo "     • Sanitize All Payload"
echo "     • Sanitize Clear Text Payload"
echo "     • Sanitize Payload and IP & MAC Addresses"
echo ""
echo -e "${BLUE}Plugin location:${NC}"
echo "  $PLUGIN_DIR/"
echo ""
echo -e "${BLUE}Files installed:${NC}"
echo "  • PacketSanitizer.lua"
echo "  • sanitize_packets.py"
echo ""
echo -e "${BLUE}Documentation:${NC}"
echo "  • README.md - Full user guide"
echo "  • INSTALL.md - Detailed installation guide"
echo ""

