#!/bin/bash
set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
validate_kernel_version() {
    local version="$1"
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+)?$ ]]; then
        echo -e "${RED}[!] Invalid kernel version format: $version${NC}"
        return 1
    fi
    return 0
}
validate_string() {
    local str="$1"
    if [[ "$str" =~ [\;\&\|\$\(] ]]; then
        echo -e "${RED}[!] String contains suspicious characters: $str${NC}"
        return 1
    fi
    return 0
}
echo -e "${YELLOW}[*] Zenith-Sentry eBPF Dependencies Installer${NC}"
echo -e "${YELLOW}[*] This script requires root privileges${NC}\n"
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Error: This script must be run as root${NC}"
    echo "    Usage: sudo bash install_ebpf_deps.sh"
    exit 1
fi
if [ -f /etc/os-release ]; then
    . /etc/os-release
    validate_string "$ID" || { echo -e "${RED}[!] Invalid OS identifier${NC}"; exit 1; }
    OS=$ID
    VERSION=$VERSION_ID
else
    echo -e "${RED}[!] Cannot detect OS version${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Detected OS: $OS $VERSION${NC}\n"
KERNEL_VERSION=$(uname -r)
validate_kernel_version "$KERNEL_VERSION" || { echo -e "${RED}[!] Invalid kernel version: $KERNEL_VERSION${NC}"; exit 1; }
if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    echo -e "${YELLOW}[*] Installing on Debian/Ubuntu...${NC}"
    echo -e "${YELLOW}[*] Updating package manager...${NC}"
    apt update && apt upgrade -y
    echo -e "${YELLOW}[*] Installing BCC toolkit...${NC}"
    apt install -y bpf-tools libbpf-dev "linux-headers-${KERNEL_VERSION}"
    echo -e "${YELLOW}[*] Installing Python development dependencies and mitigation tools...${NC}"
    apt install -y python3-dev python3-pip iptables
    echo -e "${YELLOW}[*] Installing BCC Python bindings...${NC}"
    pip3 install bcc
elif [[ "$OS" == "fedora" || "$OS" == "rhel" || "$OS" == "centos" ]]; then
    echo -e "${YELLOW}[*] Installing on Fedora/RHEL/CentOS...${NC}"
    echo -e "${YELLOW}[*] Updating package manager...${NC}"
    dnf update -y
    echo -e "${YELLOW}[*] Installing BCC toolkit...${NC}"
    dnf install -y bcc-tools libbpf-devel kernel-devel
    echo -e "${YELLOW}[*] Installing Python development dependencies and mitigation tools...${NC}"
    dnf install -y python3-devel python3-pip iptables
    echo -e "${YELLOW}[*] Installing BCC Python bindings...${NC}"
    pip3 install bcc
else
    echo -e "${RED}[!] Unsupported OS: $OS${NC}"
    echo "    Supported: Ubuntu, Debian, Fedora, RHEL, CentOS"
    exit 1
fi
echo -e "\n${YELLOW}[*] Verifying kernel eBPF support...${NC}"
if grep -q "CONFIG_BPF=y" "/boot/config-${KERNEL_VERSION}"; then
    echo -e "${GREEN}[+] CONFIG_BPF=y (eBPF enabled)${NC}"
else
    echo -e "${RED}[!] CONFIG_BPF not enabled in kernel${NC}"
    exit 1
fi
if grep -q "CONFIG_BPF_SYSCALL=y" "/boot/config-${KERNEL_VERSION}"; then
    echo -e "${GREEN}[+] CONFIG_BPF_SYSCALL=y (BPF syscall enabled)${NC}"
else
    echo -e "${RED}[!] CONFIG_BPF_SYSCALL not enabled in kernel${NC}"
    exit 1
fi
if grep -q "CONFIG_BPF_JIT=y" "/boot/config-${KERNEL_VERSION}"; then
    echo -e "${GREEN}[+] CONFIG_BPF_JIT=y (eBPF JIT enabled)${NC}"
else
    echo -e "${YELLOW}[!] CONFIG_BPF_JIT not enabled (performance will be lower)${NC}"
fi
if grep -q "CONFIG_KPROBES=y" "/boot/config-${KERNEL_VERSION}"; then
    echo -e "${GREEN}[+] CONFIG_KPROBES=y (kprobes enabled)${NC}"
else
    echo -e "${RED}[!] CONFIG_KPROBES not enabled in kernel${NC}"
    exit 1
fi
echo -e "\n${YELLOW}[*] Verifying BCC installation...${NC}"
if python3 -c "from bcc import BPF; print('BCC imported successfully')" 2>/dev/null; then
    echo -e "${GREEN}[+] BCC Python bindings installed and functional${NC}"
else
    echo -e "${RED}[!] BCC Python bindings not functional${NC}"
    exit 1
fi
echo -e "\n${YELLOW}[*] Testing eBPF program compilation...${NC}"
cat > /tmp/test_ebpf.py << 'EOF'
from bcc import BPF
test_program = """
BPF_PERF_OUTPUT(events);
int hello(void *ctx) {
    events.perf_submit(ctx, 0, 0);
    return 0;
}
"""
try:
    bpf = BPF(text=test_program)
    print("SUCCESS: eBPF compilation test passed")
except Exception as e:
    print(f"FAILED: {e}")
    exit(1)
EOF
python3 /tmp/test_ebpf.py
rm /tmp/test_ebpf.py
echo -e "\n${GREEN}[+] All eBPF dependencies installed successfully!${NC}"
echo -e "${GREEN}[+] Zenith-Sentry is ready for kernel-level monitoring${NC}"
echo -e "\n${YELLOW}[*] Next steps:${NC}"
echo "    1. Run scans with eBPF enabled:"
echo "       sudo python3 main.py full-scan --ebpf"
echo "    2. Or run the standalone monitor:"
echo "       sudo python3 process_execve_monitor.py --source zenith/ebpf/execve_monitor.c"
echo ""
