#!/bin/bash
# SMCP Security Framework - One-Command Installation Script
# Usage: curl -sSL https://get.smcp-security.dev | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SMCP_VERSION="1.0.0"
PYTHON_MIN_VERSION="3.11"
INSTALL_DIR="$HOME/.smcp-security"
CONFIG_FILE="$HOME/.smcp-security/config.json"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        return 1
    fi
    return 0
}

version_compare() {
    # Compare version strings
    if [[ "$1" == "$2" ]]; then
        return 0
    fi
    local IFS=.
    local i ver1=($1) ver2=($2)
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
        ver1[i]=0
    done
    for ((i=0; i<${#ver1[@]}; i++)); do
        if [[ -z ${ver2[i]} ]]; then
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]})); then
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then
            return 2
        fi
    done
    return 0
}

detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

check_python() {
    log_info "Checking Python installation..."
    
    if ! check_command python3; then
        log_error "Python 3 is not installed. Please install Python 3.11 or later."
        return 1
    fi
    
    local python_version
    python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    
    version_compare "$python_version" "$PYTHON_MIN_VERSION"
    local result=$?
    
    if [[ $result -eq 2 ]]; then
        log_error "Python $python_version found, but Python $PYTHON_MIN_VERSION or later is required."
        return 1
    fi
    
    log_success "Python $python_version found"
    return 0
}

check_pip() {
    log_info "Checking pip installation..."
    
    if ! check_command pip3; then
        log_warning "pip3 not found, trying to install..."
        python3 -m ensurepip --upgrade
        if ! check_command pip3; then
            log_error "Failed to install pip3"
            return 1
        fi
    fi
    
    log_success "pip3 found"
    return 0
}

install_smcp() {
    log_info "Installing SMCP Security Framework..."
    
    # Create virtual environment
    if [[ ! -d "$INSTALL_DIR" ]]; then
        mkdir -p "$INSTALL_DIR"
    fi
    
    cd "$INSTALL_DIR"
    
    if [[ ! -d "venv" ]]; then
        log_info "Creating virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install SMCP Security
    log_info "Installing smcp-security package..."
    pip install smcp-security
    
    log_success "SMCP Security Framework installed successfully"
}

create_config() {
    log_info "Creating default configuration..."
    
    cat > "$CONFIG_FILE" << EOF
{
  "security": {
    "validation_strictness": "standard",
    "enable_mfa": false,
    "enable_rbac": true,
    "enable_rate_limiting": true,
    "default_rate_limit": 100,
    "enable_encryption": true,
    "enable_ai_immune": true,
    "anomaly_threshold": 0.7,
    "enable_audit_logging": true,
    "log_level": "INFO"
  },
  "server": {
    "host": "0.0.0.0",
    "port": 8080,
    "workers": 1
  },
  "api": {
    "enable_cors": true,
    "cors_origins": ["*"],
    "enable_docs": true
  }
}
EOF
    
    log_success "Configuration file created at $CONFIG_FILE"
}

create_wrapper_script() {
    log_info "Creating wrapper script..."
    
    local wrapper_script="$INSTALL_DIR/smcp-security"
    
    cat > "$wrapper_script" << EOF
#!/bin/bash
# SMCP Security Framework Wrapper Script

SMCP_DIR="$INSTALL_DIR"
CONFIG_FILE="$CONFIG_FILE"

# Activate virtual environment
source "\$SMCP_DIR/venv/bin/activate"

# Run SMCP Security CLI
python -m smcp_security.cli "\$@" --config "\$CONFIG_FILE"
EOF
    
    chmod +x "$wrapper_script"
    
    # Add to PATH if not already there
    local shell_rc
    if [[ -n "$BASH_VERSION" ]]; then
        shell_rc="$HOME/.bashrc"
    elif [[ -n "$ZSH_VERSION" ]]; then
        shell_rc="$HOME/.zshrc"
    else
        shell_rc="$HOME/.profile"
    fi
    
    if [[ -f "$shell_rc" ]] && ! grep -q "$INSTALL_DIR" "$shell_rc"; then
        echo "" >> "$shell_rc"
        echo "# SMCP Security Framework" >> "$shell_rc"
        echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$shell_rc"
        log_info "Added $INSTALL_DIR to PATH in $shell_rc"
    fi
    
    log_success "Wrapper script created at $wrapper_script"
}

run_self_test() {
    log_info "Running self-test..."
    
    cd "$INSTALL_DIR"
    source venv/bin/activate
    
    if python -m smcp_security.cli --self-test --config "$CONFIG_FILE"; then
        log_success "Self-test passed"
        return 0
    else
        log_error "Self-test failed"
        return 1
    fi
}

show_next_steps() {
    log_success "SMCP Security Framework installation completed!"
    echo ""
    echo "Next steps:"
    echo "  1. Restart your shell or run: source ~/.bashrc"
    echo "  2. Test the installation: smcp-security --check-system"
    echo "  3. Start the security server: smcp-security --server"
    echo "  4. View documentation: https://smcp-security.dev"
    echo ""
    echo "Configuration file: $CONFIG_FILE"
    echo "Installation directory: $INSTALL_DIR"
    echo ""
    echo "Quick commands:"
    echo "  smcp-security --help          # Show help"
    echo "  smcp-security --server        # Start API server"
    echo "  smcp-security --scan          # Security scan"
    echo "  smcp-security --report        # Generate report"
    echo ""
}

cleanup_on_error() {
    log_error "Installation failed. Cleaning up..."
    if [[ -d "$INSTALL_DIR" ]]; then
        rm -rf "$INSTALL_DIR"
    fi
    exit 1
}

# Main installation function
main() {
    echo ""
    echo "🛡️  SMCP Security Framework Installer"
    echo "====================================="
    echo ""
    
    # Detect OS
    local os
    os=$(detect_os)
    log_info "Detected OS: $os"
    
    if [[ "$os" == "unknown" ]]; then
        log_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
    
    # Set up error handling
    trap cleanup_on_error ERR
    
    # Check prerequisites
    check_python || exit 1
    check_pip || exit 1
    
    # Install SMCP Security
    install_smcp
    
    # Create configuration
    create_config
    
    # Create wrapper script
    create_wrapper_script
    
    # Run self-test
    run_self_test || log_warning "Self-test failed, but installation may still work"
    
    # Show next steps
    show_next_steps
}

# Check if running with sudo (not recommended)
if [[ $EUID -eq 0 ]]; then
    log_warning "Running as root is not recommended. Consider running as a regular user."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Run main installation
main "$@"
