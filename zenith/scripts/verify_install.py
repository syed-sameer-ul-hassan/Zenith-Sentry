#!/usr/bin/env python3
"""
Installation verification script for Zenith-Sentry.
Verifies that all components are properly installed and configured.
"""
import sys
import os
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_python_version():
    """Check Python version compatibility."""
    print("Checking Python version...")
    version = sys.version_info
    if version.major != 3 or version.minor < 8:
        print(f"  ✗ Python 3.8+ required, found {version.major}.{version.minor}.{version.micro}")
        return False
    print(f"  ✓ Python {version.major}.{version.minor}.{version.micro}")
    return True

def check_dependencies():
    """Check required Python dependencies."""
    print("Checking dependencies...")
    required_packages = [
        "psutil",
        "yaml",
        "cryptography",
    ]
    
    optional_packages = [
        "bcc",
    ]
    
    all_ok = True
    for package in required_packages:
        try:
            __import__(package)
            print(f"  ✓ {package}")
        except ImportError:
            print(f"  ✗ {package} (required)")
            all_ok = False
    
    for package in optional_packages:
        try:
            __import__(package)
            print(f"  ✓ {package} (optional)")
        except ImportError:
            print(f"  ⚠ {package} (optional - not installed)")
    
    return all_ok

def check_config_file():
    """Check if config file exists."""
    print("Checking configuration...")
    config_paths = [
        "config.yaml",
        "/etc/zenith-sentry/config.yaml",
        os.path.expanduser("~/.config/zenith-sentry/config.yaml")
    ]
    
    for path in config_paths:
        if os.path.exists(path):
            print(f"  ✓ Config file found at {path}")
            return True
    
    print("  ⚠ No config file found (will use defaults)")
    return True

def check_directories():
    """Check if required directories exist."""
    print("Checking directories...")
    required_dirs = [
        "zenith",
        "zenith/utils",
        "zenith/security",
        "zenith/plugins",
        "zenith/db",
        "zenith/api",
        "zenith/monitoring",
        "zenith/cli",
    ]
    
    all_ok = True
    for dir_path in required_dirs:
        if os.path.isdir(dir_path):
            print(f"  ✓ {dir_path}")
        else:
            print(f"  ✗ {dir_path} (required)")
            all_ok = False
    
    return all_ok

def check_ebpf_source():
    """Check if eBPF source file exists."""
    print("Checking eBPF source...")
    ebpf_paths = [
        "zenith/ebpf/execve_monitor.c",
        "zenith/ebpf/execve_monitor.h",
    ]
    
    for path in ebpf_paths:
        if os.path.exists(path):
            print(f"  ✓ {path}")
        else:
            print(f"  ⚠ {path} (optional - eBPF monitoring disabled)")
    
    return True

def check_permissions():
    """Check file permissions."""
    print("Checking file permissions...")
    critical_files = [
        "config.yaml",
        "zenith/security/encryption.py",
        "zenith/db/models.py",
    ]
    
    for file_path in critical_files:
        if os.path.exists(file_path):
            stat_info = os.stat(file_path)
            mode = stat_info.st_mode
                                                 
            if mode & 0o044:
                print(f"  ⚠ {file_path} is world-readable (consider restricting)")
            else:
                print(f"  ✓ {file_path} permissions OK")
    
    return True

def check_imports():
    """Check if core modules can be imported."""
    print("Checking module imports...")
    
    modules_to_check = [
        ("zenith.utils.validation", "Validation utilities"),
        ("zenith.utils.logging", "Logging utilities"),
        ("zenith.utils.signals", "Signal handling"),
        ("zenith.security.encryption", "Encryption module"),
        ("zenith.security.event_logger", "Event logger"),
        ("zenith.config", "Configuration"),
        ("zenith.api.main", "API module"),
        ("zenith.monitoring.metrics", "Monitoring metrics"),
        ("zenith.monitoring.health", "Health checks"),
        ("zenith.monitoring.alerts", "Alerting"),
        ("zenith.db.base", "Database base"),
        ("zenith.db.models", "Database models"),
        ("zenith.db.repository", "Database repository"),
    ]
    
    all_ok = True
    for module_name, description in modules_to_check:
        try:
            __import__(module_name)
            print(f"  ✓ {description}")
        except ImportError as e:
            print(f"  ✗ {description}: {e}")
            all_ok = False
    
    return all_ok

def main():
    """Run all verification checks."""
    print("=" * 60)
    print("Zenith-Sentry Installation Verification")
    print("=" * 60)
    print()
    
    checks = [
        ("Python version", check_python_version),
        ("Dependencies", check_dependencies),
        ("Configuration", check_config_file),
        ("Directories", check_directories),
        ("eBPF source", check_ebpf_source),
        ("File permissions", check_permissions),
        ("Module imports", check_imports),
    ]
    
    results = []
    for name, check_func in checks:
        print(f"\n{name}:")
        result = check_func()
        results.append((name, result))
    
    print("\n" + "=" * 60)
    print("Summary:")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")
    
    print(f"\nTotal: {passed}/{total} checks passed")
    
    if passed == total:
        print("\n✓ Installation verification successful!")
        return 0
    else:
        print("\n✗ Installation verification failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
