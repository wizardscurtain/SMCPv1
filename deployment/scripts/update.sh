#!/bin/bash
# SMCP Security Framework - Update Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
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

check_installation() {
    if [[ ! -d "$INSTALL_DIR" ]]; then
        log_error "SMCP Security Framework is not installed"
        log_info "To install, run: curl -sSL https://get.smcp-security.dev | bash"
        exit 1
    fi
    
    if [[ ! -f "$INSTALL_DIR/venv/bin/activate" ]]; then
        log_error "Virtual environment not found. Installation may be corrupted."
        log_info "Please reinstall: curl -sSL https://get.smcp-security.dev | bash"
        exit 1
    fi
}

get_current_version() {
    cd "$INSTALL_DIR"
    source venv/bin/activate
    
    local version
    version=$(python -c "import smcp_security; print(smcp_security.__version__)" 2>/dev/null || echo "unknown")
    echo "$version"
}

get_latest_version() {
    # Check PyPI for latest version
    local latest
    latest=$(curl -s https://pypi.org/pypi/smcp-security/json | python3 -c "import sys, json; print(json.load(sys.stdin)['info']['version'])" 2>/dev/null || echo "unknown")
    echo "$latest"
}

backup_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        local backup_file="$CONFIG_FILE.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$CONFIG_FILE" "$backup_file"
        log_info "Configuration backed up to $backup_file"
    fi
}

update_package() {
    log_info "Updating SMCP Security Framework..."
    
    cd "$INSTALL_DIR"
    source venv/bin/activate
    
    # Upgrade pip first
    pip install --upgrade pip
    
    # Update smcp-security
    pip install --upgrade smcp-security
    
    log_success "Package updated successfully"
}

run_post_update_checks() {
    log_info "Running post-update checks..."
    
    cd "$INSTALL_DIR"
    source venv/bin/activate
    
    # Run self-test
    if python -m smcp_security.cli --self-test --config "$CONFIG_FILE" >/dev/null 2>&1; then
        log_success "Post-update self-test passed"
    else
        log_warning "Post-update self-test failed. The update may have issues."
    fi
    
    # Check system
    if python -m smcp_security.cli --check-system >/dev/null 2>&1; then
        log_success "System check passed"
    else
        log_warning "System check failed. Some features may not work correctly."
    fi
}

show_update_summary() {
    local old_version="$1"
    local new_version="$2"
    
    log_success "SMCP Security Framework update completed!"
    echo ""
    echo "Update Summary:"
    echo "  Previous version: $old_version"
    echo "  Current version:  $new_version"
    echo ""
    echo "Configuration file: $CONFIG_FILE"
    echo "Installation directory: $INSTALL_DIR"
    echo ""
    echo "To verify the update:"
    echo "  smcp-security --version"
    echo "  smcp-security --check-system"
    echo ""
}

# Main update function
main() {
    echo ""
    echo "🔄 SMCP Security Framework Updater"
    echo "=================================="
    echo ""
    
    # Check if installed
    check_installation
    
    # Get current version
    log_info "Checking current version..."
    local current_version
    current_version=$(get_current_version)
    log_info "Current version: $current_version"
    
    # Get latest version
    log_info "Checking for updates..."
    local latest_version
    latest_version=$(get_latest_version)
    
    if [[ "$latest_version" == "unknown" ]]; then
        log_warning "Could not check for latest version. Proceeding with update anyway..."
    else
        log_info "Latest version: $latest_version"
        
        if [[ "$current_version" == "$latest_version" ]]; then
            log_success "Already up to date!"
            exit 0
        fi
    fi
    
    # Backup configuration
    backup_config
    
    # Update package
    update_package
    
    # Get new version
    local new_version
    new_version=$(get_current_version)
    
    # Run post-update checks
    run_post_update_checks
    
    # Show summary
    show_update_summary "$current_version" "$new_version"
}

# Handle command line arguments
case "${1:-}" in
    --check-only)
        check_installation
        current_version=$(get_current_version)
        latest_version=$(get_latest_version)
        echo "Current: $current_version"
        echo "Latest:  $latest_version"
        if [[ "$current_version" != "$latest_version" ]]; then
            echo "Update available"
            exit 1
        else
            echo "Up to date"
            exit 0
        fi
        ;;
    --help|-h)
        echo "SMCP Security Framework Update Script"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --check-only    Check for updates without installing"
        echo "  --help, -h      Show this help message"
        echo ""
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
