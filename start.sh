#!/bin/bash
set -euo pipefail
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'
readonly VENV_DIR=".venv"
readonly PYYAML_VERSION="6.0.1"
readonly PYYAML_URL="https://files.pythonhosted.org/packages/source/P/PyYAML/PyYAML-${PYYAML_VERSION}.tar.gz"
readonly PYYAML_HASH="d584d9ec91ad65861573340e50516557a72c3c6877d8c85bdc9651b3ec21f0a9"
log_info() { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
trap 'log_error "Setup failed at line $LINENO"; exit 1' ERR
check_python3() {
    log_info "Checking Python 3 installation..."
    if ! command -v python3 &>/dev/null; then
        log_error "Python 3 not found"
        exit 1
    fi
    local ver
    ver=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    log_success "Python 3 found: $ver"
    if ! python3 -c "import sys; sys.exit(0 if tuple(map(int, sys.version_info[:2])) >= (3, 8) else 1)" 2>/dev/null; then
        log_error "Python 3.8+ required"
        exit 1
    fi
}
setup_venv() {
    log_info "Creating virtual environment..."
    if ! python3 -m venv "$VENV_DIR" 2>/dev/null; then
        log_error "Failed to create venv"
        exit 1
    fi
    source "$VENV_DIR/bin/activate" || { log_error "Failed to activate venv"; exit 1; }
    log_success "Virtual environment activated"
}
verify_hash() {
    if command -v sha256sum &>/dev/null; then
        if echo "${PYYAML_HASH}  pyyaml.tar.gz" | sha256sum -c - &>/dev/null 2>&1; then
            return 0
        else
            log_error "PyYAML checksum mismatch"
            return 1
        fi
    fi
    log_warning "sha256sum unavailable - skipping hash check"
    return 0
}
install_pyyaml() {
    log_info "Installing PyYAML $PYYAML_VERSION..."
    local temp_dir
    temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" RETURN
    cd "$temp_dir"
    local retries=3
    while [[ $retries -gt 0 ]]; do
        if curl -sSL --connect-timeout 10 --max-time 30 -o pyyaml.tar.gz "$PYYAML_URL" 2>/dev/null; then
            break
        fi
        retries=$((retries - 1))
        [[ $retries -gt 0 ]] && sleep 2
    done
    [[ $retries -eq 0 ]] && { log_error "PyYAML download failed"; exit 1; }
    if ! verify_hash; then
        exit 1
    fi
    if ! tar -xzf pyyaml.tar.gz 2>/dev/null; then
        log_error "PyYAML extraction failed"
        exit 1
    fi
    cd "PyYAML-${PYYAML_VERSION}"
    if python3 setup.py install --quiet 2>/dev/null; then
        log_success "PyYAML installed"
    else
        log_warning "setup.py failed, trying pip..."
        if ! pip3 install pyyaml=="$PYYAML_VERSION" --quiet 2>/dev/null; then
            log_error "PyYAML installation failed"
            exit 1
        fi
    fi
}
install_psutil() {
    log_info "Installing psutil..."
    if ! pip3 install psutil==5.9.8 --quiet 2>/dev/null; then
        log_error "psutil installation failed"
        exit 1
    fi
    log_success "psutil installed"
}
setup_ebpf() {
    log_info "Setting up optional eBPF kernel monitoring..."
    [[ $EUID -ne 0 ]] && { log_info "Run with sudo for eBPF support"; return 0; }
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        case "$ID" in
            ubuntu|debian)
                apt-get update -qq 2>/dev/null && apt-get install -y bpf-tools libbpf-dev linux-headers-$(uname -r) python3-dev iptables 2>&1 | grep -v "^Get:" || true
                ;;
            fedora|rhel|centos)
                dnf install -y bcc-tools libbpf-devel kernel-devel python3-devel iptables 2>&1 | grep -v "^" || true
                ;;
            *) log_warning "Unknown OS: $ID"; return 1 ;;
        esac
    fi
    if pip3 install bcc --quiet 2>/dev/null; then
        log_success "BCC (eBPF) installed"
    else
        log_warning "BCC installation incomplete"
    fi
}
verify_installation() {
    log_info "Verifying installation..."
    local ok=1
    python3 -c "import sys" 2>/dev/null && log_success "Python OK" || ok=0
    python3 -c "import yaml" 2>/dev/null && log_success "PyYAML OK" || ok=0
    python3 -c "import psutil" 2>/dev/null && log_success "psutil OK" || ok=0
    python3 -c "from bcc import BPF" 2>/dev/null && log_success "BCC OK" || log_warning "BCC not available (optional)"
    return $ok
}
main() {
    clear
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}   ZENITH-SENTRY Unified Setup${NC}"
    echo -e "${GREEN}   Linux EDR with eBPF Monitoring${NC}"
    echo -e "${GREEN}========================================${NC}\n"
    check_python3
    if [[ ! -d "$VENV_DIR" ]]; then
        setup_venv
        install_pyyaml
        install_psutil
    else
        log_success "Virtual environment found"
        source "$VENV_DIR/bin/activate" || { log_error "Failed to activate venv"; exit 1; }
    fi
    [[ $EUID -eq 0 ]] && setup_ebpf
    verify_installation || { log_error "Verification failed"; exit 1; }
    [[ ! -f "gui.py" ]] && { log_error "gui.py not found"; exit 1; }
    log_success "All checks passed!"
    log_info "Starting Zenith-Sentry TUI...\n"
    python3 gui.py && log_success "Session completed" || { log_error "GUI failed"; exit 1; }
}
main "$@"
