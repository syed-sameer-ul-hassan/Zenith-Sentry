#!/bin/bash
set -e

VERSION="2.1.0.0"
REPO="syed-sameer-ul-hassan/Zenith-Sentry"
INSTALL_DIR="/opt/zenith-sentry"
SERVICE_NAME="zenith-sentry"

log_info() {
    echo "[+] $1"
}

log_error() {
    echo "[!] $1" >&2
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root or with sudo"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi
    log_info "Detected OS: $OS $VERSION"
}

install_dependencies() {
    log_info "Installing dependencies..."
    case $OS in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y python3 python3-pip python3-venv git curl
            ;;
        fedora|rhel|centos)
            dnf install -y python3 python3-pip git curl
            ;;
        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

install_zenith_sentry() {
    log_info "Installing Zenith-Sentry v${VERSION}..."
    
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    
    if [ -d ".git" ]; then
        log_info "Updating existing installation..."
        git pull origin main
    else
        log_info "Cloning repository..."
        git clone "https://github.com/${REPO}.git" .
    fi
    
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    
    log_info "Installing eBPF dependencies..."
    bash install_ebpf_deps.sh || log_error "eBPF dependency installation failed, continuing..."
    
    chmod +x start.sh
    chmod +x process_execve_monitor.py
}

create_systemd_service() {
    log_info "Creating systemd service..."
    cp zenith-sentry.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable zenith-sentry
}

verify_installation() {
    log_info "Verifying installation..."
    source "$INSTALL_DIR/venv/bin/activate"
    python3 -c "import zenith; print(f'Zenith-Sentry {zenith.__version__} installed successfully')"
}

main() {
    log_info "Zenith-Sentry v${VERSION} Installation"
    log_info "=========================================="
    
    check_root
    detect_os
    install_dependencies
    install_zenith_sentry
    create_systemd_service
    verify_installation
    
    log_info "Installation complete!"
    log_info "Start service: sudo systemctl start zenith-sentry"
    log_info "Check status: sudo systemctl status zenith-sentry"
    log_info "Run manually: cd $INSTALL_DIR && ./start.sh"
}

main
