#!/bin/bash
# SMCP Security Framework - Uninstallation Script

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

remove_installation() {
    log_info "Removing SMCP Security Framework installation..."
    
    if [[ -d "$INSTALL_DIR" ]]; then
        rm -rf "$INSTALL_DIR"
        log_success "Installation directory removed: $INSTALL_DIR"
    else
        log_warning "Installation directory not found: $INSTALL_DIR"
    fi
}

remove_from_path() {
    log_info "Removing from PATH..."
    
    local shell_files=("$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile")
    
    for shell_file in "${shell_files[@]}"; do
        if [[ -f "$shell_file" ]]; then
            # Remove SMCP lines from shell config
            if grep -q "SMCP Security Framework" "$shell_file"; then
                # Create backup
                cp "$shell_file" "$shell_file.smcp-backup"
                
                # Remove SMCP lines
                sed -i '/# SMCP Security Framework/,+1d' "$shell_file"
                
                log_success "Removed SMCP from $shell_file (backup created)"
            fi
        fi
    done
}

remove_pip_package() {
    log_info "Checking for global pip installation..."
    
    if pip3 list | grep -q "smcp-security"; then
        log_info "Found global smcp-security package, removing..."
        pip3 uninstall -y smcp-security
        log_success "Global smcp-security package removed"
    else
        log_info "No global smcp-security package found"
    fi
}

clean_cache() {
    log_info "Cleaning cache and temporary files..."
    
    # Remove pip cache
    if [[ -d "$HOME/.cache/pip" ]]; then
        rm -rf "$HOME/.cache/pip/wheels/smcp*"
        rm -rf "$HOME/.cache/pip/http/smcp*"
    fi
    
    # Remove Python cache
    find "$HOME" -name "__pycache__" -path "*smcp*" -type d -exec rm -rf {} + 2>/dev/null || true
    find "$HOME" -name "*.pyc" -path "*smcp*" -delete 2>/dev/null || true
    
    log_success "Cache cleaned"
}

show_completion() {
    log_success "SMCP Security Framework uninstallation completed!"
    echo ""
    echo "What was removed:"
    echo "  ✓ Installation directory: $INSTALL_DIR"
    echo "  ✓ Configuration files"
    echo "  ✓ PATH entries (backups created)"
    echo "  ✓ Global pip package (if installed)"
    echo "  ✓ Cache files"
    echo ""
    echo "Note: You may need to restart your shell for PATH changes to take effect."
    echo ""
    echo "If you want to reinstall later:"
    echo "  curl -sSL https://get.smcp-security.dev | bash"
    echo ""
}

# Main uninstallation function
main() {
    echo ""
    echo "🗑️  SMCP Security Framework Uninstaller"
    echo "======================================="
    echo ""
    
    # Confirm uninstallation
    read -p "Are you sure you want to uninstall SMCP Security Framework? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Uninstallation cancelled"
        exit 0
    fi
    
    # Check if installed
    if [[ ! -d "$INSTALL_DIR" ]]; then
        log_warning "SMCP Security Framework does not appear to be installed"
        log_info "Checking for global pip installation..."
        remove_pip_package
        clean_cache
        log_success "Cleanup completed"
        exit 0
    fi
    
    # Remove installation
    remove_installation
    
    # Remove from PATH
    remove_from_path
    
    # Remove global pip package if exists
    remove_pip_package
    
    # Clean cache
    clean_cache
    
    # Show completion message
    show_completion
}

# Run main uninstallation
main "$@"
