# Zenith-Sentry v2.1.0.0 Release Notes

## Overview

Zenith-Sentry v2.1.0.0 represents a significant milestone in the evolution of our Linux Endpoint Detection and Response (EDR) toolkit. This release introduces architectural improvements, enhanced documentation, and expanded capabilities for production-grade security monitoring.

## Quick Installation

Install Zenith-Sentry v2.1.0.0 with a single command:

```bash
curl -fsSL https://raw.githubusercontent.com/syed-sameer-ul-hassan/Zenith-Sentry/main/install.sh | sudo bash
```

## What's New

### Architecture Restructuring

The codebase has been reorganized into a modular, production-ready architecture:

- **REST API Layer** (`zenith/api/`): Full FastAPI implementation with authentication, authorization, and comprehensive endpoints for scans, findings, system monitoring, and defense operations
- **Command-Line Interface** (`zenith/cli/`): Dedicated CLI module with improved command structure and argument parsing
- **Database Layer** (`zenith/db/`): SQLAlchemy-based ORM with models, repository pattern, and data retention policies
- **Monitoring & Metrics** (`zenith/monitoring/`): Prometheus metrics integration, health checks, and alerting capabilities
- **Security Utilities** (`zenith/security/`): Encryption utilities and security event logging
- **Utility Functions** (`zenith/utils/`): Shared utilities for validation, logging, and signal handling
- **Configuration Management** (`zenith/config/`): Centralized configuration with FHS/XDG path management
- **Scripts** (`zenith/scripts/`): Backup, restore, and installation verification utilities

### Enhanced Documentation

- **Architecture Documentation** (`docs/architecture.md`): Comprehensive system architecture overview with data flow diagrams, module structure, and database schema
- **Deployment Guide** (`docs/deployment.md`): Production deployment strategies including Docker, Kubernetes, and systemd configurations
- **Security Documentation** (`docs/security.md`): Security best practices, threat model, and hardening guidelines
- **Troubleshooting Guide** (`docs/troubleshooting.md`): Common issues and solutions
- **eBPF Implementation Guide** (`zenith/ebpf/EBPF_GUIDE.md`): Detailed technical documentation for eBPF kernel monitoring subsystem

### Web Interface

- **Web Dashboard** (`web/`): Modern, responsive web interface built with vanilla HTML, CSS, and JavaScript
- **Real-time Monitoring**: Live threat detection and system status visualization
- **Interactive Controls**: Web-based mitigation and configuration management

### CI/CD Pipeline

- **GitHub Actions Workflows**: Automated testing, security scanning, and code quality checks
- **Continuous Integration**: Automated testing on push and pull requests
- **Security Scanning**: Bandit and Safety checks for vulnerability detection
- **Code Quality**: Black formatting, Flake8 linting, and MyPy type checking

### Modern Python Packaging

- **pyproject.toml**: Modern Python packaging configuration following PEP 621
- **Build System**: setuptools-based build with wheel support
- **Development Dependencies**: Comprehensive dev dependencies for testing, linting, and security scanning

### Systemd Service

- **Production Service**: systemd service file for production deployment
- **Auto-start**: Automatic service startup on boot
- **Process Management**: Proper process lifecycle management

## Improvements

### Documentation Quality

- Fixed all ASCII diagrams in README.md and EBPF_GUIDE.md
- Enhanced Table of Contents with descriptions
- Updated module structure documentation to reflect actual codebase
- Added comprehensive API documentation
- Improved architectural diagrams with consistent styling

### Code Organization

- Separated concerns into distinct modules
- Improved code reusability and maintainability
- Better dependency injection patterns
- Enhanced error handling and logging

### Security Enhancements

- JWT token authentication for API
- Role-based access control (RBAC)
- API key authentication support
- Secure logging with PII redaction
- Security event correlation

### Configuration Management

- Centralized configuration with YAML support
- Environment variable support
- Configuration validation
- Safe-default injection for missing keys

### Monitoring & Observability

- Prometheus metrics integration
- Health check endpoints
- Alerting capabilities
- Performance monitoring

## Technical Details

### Version Information

- **Version**: 2.1.0.0
- **Python**: 3.8+
- **Kernel**: 5.8+ (for eBPF support)
- **Platform**: Linux

### Dependencies

Core dependencies:
- psutil>=5.9.8
- pyyaml>=6.0.1
- cryptography>=41.0.7

eBPF dependencies (optional):
- bcc>=0.5.0

Development dependencies:
- pytest>=7.4.3
- pytest-cov>=4.1.0
- black>=23.12.1
- flake8>=6.1.0
- mypy>=1.7.1
- bandit>=1.7.6
- safety>=2.3.5

### Installation Methods

1. **One-line Install** (Recommended):
   ```bash
   curl -fsSL https://raw.githubusercontent.com/syed-sameer-ul-hassan/Zenith-Sentry/main/install.sh | sudo bash
   ```

2. **Manual Install**:
   ```bash
   git clone https://github.com/syed-sameer-ul-hassan/Zenith-Sentry.git
   cd Zenith-Sentry
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **From Source**:
   ```bash
   pip install git+https://github.com/syed-sameer-ul-hassan/Zenith-Sentry.git
   ```

### Configuration

Configuration is managed through `config.yaml`:

```yaml
ebpf:
  enabled: true
  watchlist:
    - /tmp
    - /dev/shm
    - /var/tmp

network:
  watch_ports:
    - 4444
    - 5555
    - 6666

mitigation:
  enforce_mode: true
  safe_mode: false
```

### Service Management

Start the service:
```bash
sudo systemctl start zenith-sentry
```

Check status:
```bash
sudo systemctl status zenith-sentry
```

View logs:
```bash
sudo journalctl -u zenith-sentry -f
```

## Breaking Changes

- **Configuration File**: Configuration structure has been updated. Existing `config.yaml` files may need to be migrated.
- **API Endpoints**: REST API endpoints have been reorganized under `/api/v1/` prefix.
- **Module Structure**: Internal module structure has changed. Custom plugins may need updates.

## Migration Guide

### From v2.0 to v2.1.0.0

1. **Backup Configuration**:
   ```bash
   cp config.yaml config.yaml.backup
   ```

2. **Update Configuration**:
   - Review new configuration options in `config.yaml`
   - Migrate custom settings to new structure
   - Test configuration validation

3. **Update Plugins**:
   - Update custom plugins to use new base classes
   - Review plugin interface changes
   - Test plugin functionality

4. **Install New Version**:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/syed-sameer-ul-hassan/Zenith-Sentry/main/install.sh | sudo bash
   ```

5. **Verify Installation**:
   ```bash
   sudo systemctl status zenith-sentry
   ```

## Known Issues

- eBPF monitoring requires kernel 5.8+ and appropriate permissions
- Web interface requires manual configuration for production use
- Some monitoring features may require additional dependencies

## Security Considerations

This release includes several security enhancements:

- No data collection or telemetry is sent to external servers
- All processing happens locally on the host
- Installation script downloads only from official GitHub repository
- No third-party dependencies in core installation
- All network operations are explicit and configurable

## Support

- **Issues**: https://github.com/syed-sameer-ul-hassan/Zenith-Sentry/issues
- **Documentation**: https://github.com/syed-sameer-ul-hassan/Zenith-Sentry#readme
- **Architecture**: docs/architecture.md
- **Troubleshooting**: docs/troubleshooting.md

## Contributors

Thanks to all contributors who made this release possible.

## License

MIT License - See LICENSE file for details

## Changelog

### Added
- REST API with FastAPI
- Web interface
- Database layer with SQLAlchemy
- Monitoring and metrics (Prometheus)
- Security utilities (encryption, event logging)
- CI/CD pipeline with GitHub Actions
- Modern Python packaging (pyproject.toml)
- Systemd service file
- Comprehensive documentation
- Deployment guides

### Changed
- Restructured codebase into modular architecture
- Updated configuration management
- Improved error handling and logging
- Enhanced documentation quality

### Fixed
- ASCII diagrams in documentation
- Module structure documentation
- Configuration path handling
- Dependency management

### Removed
- Legacy GUI (replaced with web interface)
- Deprecated configuration options
