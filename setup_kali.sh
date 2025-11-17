#!/bin/bash
# OWASP WSTG Framework - Kali Linux Setup Script
# Automates installation of dependencies and tools for Kali Linux

set -e

echo "=========================================="
echo "OWASP WSTG Framework - Kali Linux Setup"
echo "=========================================="
echo "Target: Kali Linux"
echo "Date: $(date)"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

print_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "Please do not run this script as root. Use a regular user account."
        exit 1
    fi
}

# Update system
update_system() {
    print_status "Updating Kali Linux package lists..."
    sudo apt update
    sudo apt upgrade -y
    print_status "System updated successfully"
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."

    # Check if Python 3 is installed
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        exit 1
    fi

    # Install pip if not present
    if ! command -v pip3 &> /dev/null; then
        print_status "Installing pip3..."
        sudo apt install python3-pip -y
    fi

    # Install requirements
    if [ -f "requirements.txt" ]; then
        print_status "Installing Python requirements from requirements.txt..."
        pip3 install -r requirements.txt
    else
        print_warning "requirements.txt not found, installing basic packages..."
        pip3 install requests beautifulsoup4 lxml certifi urllib3 pydantic faker
        pip3 install dnspython python-whois pyopenssl cryptography
        pip3 install selenium webdriver-manager
    fi
}

# Install Kali Linux security tools
install_kali_tools() {
    print_status "Installing Kali Linux security tools..."

    # Essential web security tools
    tools=(
        "nmap"
        "nikto"
        "hydra"
        "dirb"
        "gobuster"
        "sqlmap"
        "wpscan"
        "curl"
        "wget"
        "john"
        "hashcat"
        "testssl.sh"
        "burpsuite"
        "zaproxy"
        "dirsearch"
        "feroxbuster"
        "ffuf"
        "wfuzz"
    )

    for tool in "${tools[@]}"; do
        print_status "Installing $tool..."
        if dpkg -l | grep -q "^ii.*$tool"; then
            print_status "$tool is already installed"
        else
            sudo apt install "$tool" -y
        fi
    done
}

# Install wordlists
install_wordlists() {
    print_status "Installing security wordlists..."

    wordlist_packages=(
        "wordlists"
        "seclists"
    )

    for pkg in "${wordlist_packages[@]}"; do
        print_status "Installing $pkg..."
        sudo apt install "$pkg" -y
    done

    # Create custom wordlists directory
    mkdir -p "$HOME/wordlists"

    # Download additional wordlists
    if [ ! -f "$HOME/wordlists/rockyou.txt" ]; then
        print_status "Downloading rockyou.txt wordlist..."
        if [ -f "/usr/share/wordlists/rockyou.txt" ]; then
            cp /usr/share/wordlists/rockyou.txt "$HOME/wordlists/"
        else
            # Download from GitHub if not available locally
            wget -O "$HOME/wordlists/rockyou.txt" \
                "https://raw.githubusercontent.com/brannondorsey/naive-bayes-classifier/master/wordlists/rockyou.txt" \
                2>/dev/null || print_warning "Could not download rockyou.txt"
        fi
    fi
}

# Setup virtual environment
setup_virtualenv() {
    print_status "Setting up Python virtual environment..."

    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi

    # Activate virtual environment
    source venv/bin/activate

    # Install dependencies in virtual environment
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
    else
        pip install requests beautifulsoup4 lxml pydantic faker selenium
        pip install dnspython python-whois pyopenssl cryptography
    fi

    print_status "Virtual environment setup complete"
    print_status "To activate: source venv/bin/activate"
}

# Configure tools
configure_tools() {
    print_status "Configuring security tools..."

    # Configure Burp Suite (if available)
    if command -v burpsuite &> /dev/null; then
        print_status "Burp Suite found. You may need to configure it manually."
        echo "Run 'burpsuite' to start the application."
    fi

    # Configure OWASP ZAP (if available)
    if command -v zaproxy &> /dev/null; then
        print_status "OWASP ZAP found. Starting ZAP daemon..."
        # You can add ZAP configuration here if needed
    fi

    # Create directories for outputs
    mkdir -p outputs
    mkdir -p logs
    mkdir -p reports

    print_status "Tool configuration complete"
}

# Setup Git and clone additional resources if needed
setup_additional_resources() {
    print_status "Setting up additional resources..."

    # Check if Git is installed
    if ! command -v git &> /dev/null; then
        print_status "Installing Git..."
        sudo apt install git -y
    fi

    # You can add additional resource downloads here
    print_status "Additional resources setup complete"
}

# Create desktop shortcuts
create_shortcuts() {
    print_status "Creating desktop shortcuts..."

    # Create scripts directory
    mkdir -p "$HOME/wstg-scripts"

    # Create run script
    cat > "$HOME/wstg-scripts/run_framework.sh" << 'EOF'
#!/bin/bash
cd /path/to/your/wstg/framework
source venv/bin/activate
python complete_wstg_framework.py "$@"
EOF

    chmod +x "$HOME/wstg-scripts/run_framework.sh"

    # Create desktop entry
    cat > "$HOME/Desktop/WSTG-Framework.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=WSTG Security Framework
Comment=OWASP Web Security Testing Guide Framework
Exec=xfce4-terminal -e "bash -c 'cd /path/to/your/wstg/framework; source venv/bin/activate; python complete_wstg_framework.py; read -p \"Press Enter to exit\"'"
Icon=security
Terminal=false
Categories=Security;Development;
EOF

    chmod +x "$HOME/Desktop/WSTG-Framework.desktop"
    print_status "Desktop shortcuts created in ~/wstg-scripts/"
    print_warning "Remember to update the path in run_framework.sh to your framework directory!"
}

# Test installation
test_installation() {
    print_status "Testing installation..."

    # Test Python
    python3 --version
    pip3 --version

    # Test key tools
    nmap --version | head -n 1
    curl --version | head -n 1
    nikto -Version 2>/dev/null | head -n 1 || print_warning "Nikto may need additional configuration"

    # Test framework import
    if [ -f "complete_wstg_framework.py" ]; then
        python3 -c "import requests; import bs4; print('Core dependencies OK')" || print_error "Core dependencies test failed"
    fi

    print_status "Installation test complete"
}

# Generate setup report
generate_report() {
    print_status "Generating setup report..."

    cat > "$HOME/wstg-setup-report.txt" << EOF
OWASP WSTG Framework - Kali Linux Setup Report
============================================
Date: $(date)
User: $(whoami)
Hostname: $(hostname)

Installation Summary:
- Python 3: $(python3 --version)
- pip3: $(pip3 --version)
- Virtual Environment: $([ -d "venv" ] && echo "Created" || echo "Not created")

Tools Installed:
- nmap: $(command -v nmap &>/dev/null && echo "Installed" || echo "Not found")
- nikto: $(command -v nikto &>/dev/null && echo "Installed" || echo "Not found")
- hydra: $(command -v hydra &>/dev/null && echo "Installed" || echo "Not found")
- dirb: $(command -v dirb &>/dev/null && echo "Installed" || echo "Not found")
- gobuster: $(command -v gobuster &>/dev/null && echo "Installed" || echo "Not found")
- sqlmap: $(command -v sqlmap &>/dev/null && echo "Installed" || echo "Not found")
- wpscan: $(command -v wpscan &>/dev/null && echo "Installed" || echo "Not found")
- burpsuite: $(command -v burpsuite &>/dev/null && echo "Installed" || echo "Not found")
- zaproxy: $(command -v zaproxy &>/dev/null && echo "Installed" || echo "Not found")

Wordlists:
- /usr/share/wordlists: $([ -d "/usr/share/wordlists" ] && echo "Available" || echo "Not found")
- ~/wordlists: $([ -d "$HOME/wordlists" ] && echo "Created" || echo "Not found")

Next Steps:
1. Source the virtual environment: source venv/bin/activate
2. Run the framework: python complete_wstg_framework.py --target example.com
3. Check the documentation in the README files
4. Customize the framework for your needs

For help, run: python complete_wstg_framework.py --help
EOF

    print_status "Setup report saved to: $HOME/wstg-setup-report.txt"
}

# Main function
main() {
    print_status "Starting OWASP WSTG Framework setup for Kali Linux..."

    check_root
    update_system
    install_python_deps
    install_kali_tools
    install_wordlists
    setup_virtualenv
    configure_tools
    setup_additional_resources
    create_shortcuts
    test_installation
    generate_report

    print_status "=========================================="
    print_status "Setup completed successfully!"
    print_status "=========================================="
    echo
    print_status "To start using the framework:"
    echo "  1. Activate virtual environment:"
    echo "     source venv/bin/activate"
    echo "  2. Run the framework:"
    echo "     python complete_wstg_framework.py --target example.com"
    echo "  3. Or use the shortcut:"
    echo "     ~/wstg-scripts/run_framework.sh --target example.com"
    echo
    print_status "For more information, check the README files in each phase directory."
    print_status "Setup report saved to: $HOME/wstg-setup-report.txt"
    echo
}

# Run main function
main "$@"