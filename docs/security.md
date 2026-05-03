# Zenith-Sentry Security Guide

This guide covers security best practices, threat modeling, and incident response for Zenith-Sentry.

## Table of Contents

- [Security Overview](#security-overview)
- [Threat Model](#threat-model)
- [Security Architecture](#security-architecture)
- [Best Practices](#best-practices)
- [Hardening Guidelines](#hardening-guidelines)
- [Incident Response](#incident-response)
- [Compliance](#compliance)

## Security Overview

Zenith-Sentry implements defense-in-depth security with multiple layers of protection:

1. **Input Validation** - All inputs are validated before processing
2. **Command Injection Prevention** - Parameterized commands and IP whitelisting
3. **Secure Signal Handling** - Safe signal handlers with proper cleanup
4. **Encryption at Rest** - AES-256 encryption for sensitive data
5. **Secure Logging** - PII redaction and security event correlation
6. **Authentication** - JWT tokens and API key authentication
7. **Authorization** - Role-based access control (RBAC)

## Threat Model

### Attack Vectors

#### 1. Command Injection
**Threat**: Attacker injects malicious commands through user input

**Mitigation**:
- Input validation for file paths and IPs
- Parameterized commands using subprocess
- IP whitelisting for network operations
- Shell command validation in scripts

```python
# Secure command execution
from subprocess import run, PIPE
from zenith.utils.validation import validate_ip, validate_file_path

ip = validate_ip(user_input)
if ip:
    result = run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
```

#### 2. Privilege Escalation
**Threat**: Attacker gains elevated privileges through vulnerabilities

**Mitigation**:
- Run as non-root user when possible
- Use systemd security hardening
- Drop unnecessary capabilities
- Use namespaces and containers

```ini
# systemd service hardening
[Service]
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN
```

#### 3. Data Exfiltration
**Threat**: Attacker extracts sensitive data from logs or database

**Mitigation**:
- Encrypt sensitive data at rest
- PII redaction in logs
- Secure database connections with TLS
- Access control on log files

```python
# Secure logging with PII redaction
from zenith.security.event_logger import SecureEventLogger

logger = SecureEventLogger(redact_pii=True)
logger.log_security_event(
    event_type="LOGIN",
    user="***@***.com",  # Will be redacted
    ip="192.168.1.1"
)
```

#### 4. Denial of Service
**Threat**: Attacker overwhelms system with requests or events

**Mitigation**:
- Rate limiting on API endpoints
- Circular buffer for eBPF events
- Memory limits on data structures
- Connection pooling for database

```yaml
# Rate limiting configuration
api:
  rate_limit:
    enabled: true
    requests_per_minute: 60
```

#### 5. Authentication Bypass
**Threat**: Attacker bypasses authentication mechanisms

**Mitigation**:
- Strong JWT secret keys
- API key hashing with bcrypt
- Token expiration
- Multi-factor authentication (MFA)

```python
# Secure token generation
from jose import jwt
from datetime import datetime, timedelta

token = jwt.encode(
    {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(hours=1)
    },
    SECRET_KEY,
    algorithm="HS256"
)
```

### Attack Surface

| Component | Risk Level | Mitigation |
|-----------|------------|------------|
| API Endpoints | High | Authentication, rate limiting, input validation |
| eBPF Monitor | High | Root required, kernel-level access |
| Database | Medium | Encryption, access control, TLS |
| Log Files | Medium | PII redaction, secure permissions |
| Configuration | Medium | Validation, secure defaults |
| Network Operations | High | IP validation, whitelisting |

## Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────────────────────┐
│                     Network Layer                        │
│  Firewall, TLS, Network Segmentation, DDoS Protection  │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                  Application Layer                       │
│  Authentication, Authorization, Rate Limiting, Input   │
│  Validation, Secure Headers, CSRF Protection           │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                   Data Layer                            │
│  Encryption at Rest, TLS in Transit, Access Control,    │
│  Audit Logging, Data Retention Policies                 │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                  System Layer                           │
│  Secure Signal Handling, Privilege Separation,          │
│  Capability Dropping, Systemd Hardening                 │
└─────────────────────────────────────────────────────────┘
```

### Security Controls

#### Authentication
- JWT tokens with expiration
- API key authentication with bcrypt hashing
- Password hashing with bcrypt
- Session management

#### Authorization
- Role-based access control (RBAC)
- Permission checks on all endpoints
- Resource-level isolation
- Audit logging of access attempts

#### Data Protection
- AES-256 encryption for sensitive data
- TLS for database connections
- PII redaction in logs
- Secure file permissions

#### Monitoring
- Security event logging
- Anomaly detection
- Alerting on suspicious activity
- Audit trail retention

## Best Practices

### Installation

1. **Use Official Sources**
   ```bash
   # Install from official repository
   pip install zenith-sentry
   # or
   git clone https://github.com/official/Zenith-Sentry.git
   ```

2. **Verify Signatures**
   ```bash
   # Verify GPG signature
   gpg --verify zenith-sentry.tar.gz.asc
   ```

3. **Run Security Verification**
   ```bash
   # Run installation verification
   python zenith/scripts/verify_install.py
   ```

### Configuration

1. **Use Strong Secrets**
   ```bash
   # Generate secure encryption key
   python -c "from zenith.security.encryption import generate_key; print(generate_key())"
   
   # Set environment variable
   export ZENITH_ENCRYPTION_KEY="your-secure-key-here"
   ```

2. **Secure Configuration File**
   ```bash
   # Set secure permissions
   sudo chmod 600 /etc/zenith-sentry/config.yaml
   sudo chown root:root /etc/zenith-sentry/config.yaml
   ```

3. **Use TLS in Production**
   ```yaml
   # Configure TLS
   database:
     url: "postgresql://zenith:password@localhost:5432/zenith?sslmode=require"
   ```

### Operation

1. **Run as Non-Root User**
   ```bash
   # Create dedicated user
   sudo useradd -r -s /bin/false zenith-sentry
   
   # Run as non-root
   sudo -u zenith-sentry zenith-sentry
   ```

2. **Use Firewall**
   ```bash
   # Configure firewall
   sudo ufw allow 8000/tcp
   sudo ufw enable
   ```

3. **Regular Updates**
   ```bash
   # Update dependencies
   pip install --upgrade -r requirements.txt
   
   # Update system
   sudo apt-get update && sudo apt-get upgrade
   ```

4. **Regular Backups**
   ```bash
   # Automated backup
   python zenith/scripts/backup.py --output /backup/zenith-$(date +%Y%m%d).db
   ```

### Development

1. **Security Testing**
   ```bash
   # Run security scans
   bandit -r zenith/
   safety check
   ```

2. **Code Review**
   - Review all code for security issues
   - Use static analysis tools
   - Perform penetration testing

3. **Dependency Scanning**
   ```bash
   # Check for vulnerabilities
   pip-audit
   ```

## Hardening Guidelines

### System Hardening

1. **Disable Unused Services**
   ```bash
   # Disable unnecessary services
   sudo systemctl disable <service>
   ```

2. **Secure SSH**
   ```bash
   # Edit /etc/ssh/sshd_config
   PermitRootLogin no
   PasswordAuthentication no
   PubkeyAuthentication yes
   ```

3. **Enable SELinux/AppArmor**
   ```bash
   # Enable SELinux
   sudo setenforce 1
   
   # Or enable AppArmor
   sudo systemctl enable apparmor
   sudo systemctl start apparmor
   ```

### Application Hardening

1. **Systemd Service Hardening**
   ```ini
   [Service]
   NoNewPrivileges=true
   PrivateTmp=true
   ProtectSystem=strict
   ProtectHome=true
   ReadOnlyPaths=/etc/zenith-sentry
   ReadWritePaths=/var/log/zenith-sentry
   CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN
   ```

2. **File Permissions**
   ```bash
   # Secure file permissions
   sudo chmod 750 /etc/zenith-sentry/
   sudo chmod 750 /var/log/zenith-sentry/
   sudo chown -R zenith-sentry:zenith-sentry /etc/zenith-sentry/
   sudo chown -R zenith-sentry:zenith-sentry /var/log/zenith-sentry/
   ```

3. **Network Hardening**
   ```bash
   # Use reverse proxy with TLS
   # nginx configuration:
   server {
       listen 443 ssl http2;
       server_name zenith-sentry.example.com;
       
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;
       ssl_protocols TLSv1.2 TLSv1.3;
       ssl_ciphers HIGH:!aNULL:!MD5;
       
       location / {
           proxy_pass http://localhost:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

### Database Hardening

1. **Enable TLS**
   ```sql
   -- PostgreSQL TLS configuration
   -- In postgresql.conf:
   ssl = on
   ssl_cert_file = 'server.crt'
   ssl_key_file = 'server.key'
   ssl_protocols = 'TLSv1.2,TLSv1.3'
   ```

2. **Strong Authentication**
   ```sql
   -- Use strong passwords
   ALTER USER zenith WITH PASSWORD 'strong-password-here';
   
   -- Enable SCRAM-SHA-256
   ALTER SYSTEM SET password_encryption = 'scram-sha-256';
   ```

3. **Row-Level Security**
   ```sql
   -- Enable RLS
   ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
   
   -- Create policy
   CREATE POLICY user_findings ON findings
       FOR SELECT
       USING (user_id = current_user_id());
   ```

## Incident Response

### Preparation

1. **Establish Incident Response Team**
   - Security team lead
   - System administrator
   - Database administrator
   - Legal counsel (if needed)

2. **Define Response Procedures**
   - Detection and analysis
   - Containment
   - Eradication
   - Recovery
   - Post-incident activity

3. **Set Up Monitoring**
   - Real-time alerts
   - Log aggregation
   - Anomaly detection
   - Security dashboards

### Detection

1. **Monitor Security Events**
   ```bash
   # View security events
   tail -f /var/log/zenith-sentry/security.log
   
   # Check for anomalies
   python -m zenith.monitoring.analyze_anomalies
   ```

2. **Review Audit Logs**
   ```bash
   # Review access logs
   grep "FAILED_LOGIN" /var/log/zenith-sentry/audit.log
   
   # Check for privilege escalation
   grep "PRIVILEGE_ESCALATION" /var/log/zenith-sentry/audit.log
   ```

3. **Analyze Findings**
   ```bash
   # Get critical findings
   curl http://localhost:8000/api/v1/findings?risk_level=critical
   
   # Check for suspicious activity
   curl http://localhost:8000/api/v1/findings?severity=high
   ```

### Containment

1. **Isolate Affected Systems**
   ```bash
   # Stop the service
   sudo systemctl stop zenith-sentry
   
   # Disconnect from network if needed
   sudo ifdown eth0
   ```

2. **Preserve Evidence**
   ```bash
   # Create memory dump
   sudo dd if=/dev/mem of=/tmp/memory.dump bs=1M count=1024
   
   # Copy logs
   sudo cp -r /var/log/zenith-sentry /tmp/evidence/
   
   # Backup database
   python zenith/scripts/backup.py --output /tmp/evidence/zenith.db
   ```

3. **Block Attackers**
   ```bash
   # Block malicious IPs
   sudo iptables -A INPUT -s <attacker-ip> -j DROP
   
   # Block malicious processes
   sudo kill -9 <malicious-pid>
   ```

### Eradication

1. **Remove Malicious Software**
   ```bash
   # Remove malicious files
   sudo rm /tmp/malicious-file
   
   # Remove malicious processes
   sudo pkill -f malicious-process
   ```

2. **Patch Vulnerabilities**
   ```bash
   # Update system
   sudo apt-get update && sudo apt-get upgrade
   
   # Update Zenith-Sentry
   pip install --upgrade zenith-sentry
   ```

3. **Change Credentials**
   ```bash
   # Change all passwords
   # Change API keys
   # Change encryption keys
   ```

### Recovery

1. **Restore from Backup**
   ```bash
   # Restore database
   python zenith/scripts/restore.py --input /backup/clean-backup.db
   
   # Verify restore
   python -m zenith.db.base verify
   ```

2. **Restart Services**
   ```bash
   # Restart Zenith-Sentry
   sudo systemctl start zenith-sentry
   
   # Verify operation
   curl http://localhost:8000/health
   ```

3. **Monitor for Recurrence**
   ```bash
   # Monitor logs
   tail -f /var/log/zenith-sentry/security.log
   
   # Check for new findings
   curl http://localhost:8000/api/v1/findings
   ```

### Post-Incident Activity

1. **Document the Incident**
   - Timeline of events
   - Actions taken
   - Lessons learned
   - Recommendations

2. **Review Security Posture**
   - Identify gaps
   - Update policies
   - Implement improvements

3. **Communicate with Stakeholders**
   - Notify affected users
   - Provide incident report
   - Share lessons learned

## Compliance

### GDPR Compliance

1. **Data Subject Rights**
   ```python
   # Implement data export
   def export_user_data(user_id):
       findings = db.query(Finding).filter_by(user_id=user_id).all()
       return serialize(findings)
   
   # Implement data deletion
   def delete_user_data(user_id):
       db.query(Finding).filter_by(user_id=user_id).delete()
       db.commit()
   ```

2. **Consent Management**
   ```python
   # Track consent
   def record_consent(user_id, consent_type):
       consent = Consent(
           user_id=user_id,
           type=consent_type,
           timestamp=datetime.utcnow(),
           granted=True
       )
       db.add(consent)
       db.commit()
   ```

3. **Data Minimization**
   - Only collect necessary data
   - Anonymize data when possible
   - Implement data retention policies

### SOC2 Compliance

1. **Security Controls**
   - Implement access controls
   - Enable audit logging
   - Regular security reviews

2. **Audit Trails**
   ```python
   # Log all user actions
   def log_user_action(user_id, action, resource):
       audit_log = AuditLog(
           user_id=user_id,
           action=action,
           resource=resource,
           timestamp=datetime.utcnow()
       )
       db.add(audit_log)
       db.commit()
   ```

3. **Incident Response**
   - Documented procedures
   - Regular testing
   - Continuous improvement

### HIPAA Compliance

1. **Protected Health Information (PHI)**
   - Encrypt PHI at rest and in transit
   - Implement access controls
   - Audit access to PHI

2. **Risk Assessment**
   - Regular security assessments
   - Vulnerability scanning
   - Penetration testing

3. **Business Associate Agreements**
   - Ensure all vendors sign BAAs
   - Review vendor security practices

## Security Checklist

### Pre-Deployment

- [ ] Review security configuration
- [ ] Verify TLS certificates
- [ ] Test authentication mechanisms
- [ ] Review file permissions
- [ ] Run security scans (bandit, safety)
- [ ] Test backup/restore procedures
- [ ] Review audit logging configuration
- [ ] Verify firewall rules
- [ ] Test incident response procedures
- [ ] Document security policies

### Post-Deployment

- [ ] Monitor security logs daily
- [ ] Review access logs weekly
- [ ] Run vulnerability scans monthly
- [ ] Update dependencies regularly
- [ ] Review user access quarterly
- [ ] Conduct security reviews annually
- [ ] Test incident response annually
- [ ] Update security policies annually

## Reporting Security Issues

If you discover a security vulnerability in Zenith-Sentry:

1. **Do not disclose publicly**
2. **Email security@zenith-sentry.com**
3. **Include details**:
   - Vulnerability description
   - Steps to reproduce
   - Impact assessment
   - Suggested fix
4. **Allow time to fix** before disclosure

## Resources

- [OWASP Security Guidelines](https://owasp.org/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [GDPR Compliance](https://gdpr.eu/)
- [SOC2 Compliance](https://www.aicpa.org/soc4so)

## Support

- **Documentation**: See [docs/](docs/) directory
- **Bug Reporting**: Report bugs at [bug Zenith Sentry](https://bug-zenith-sentry.orldo.sbs)
- **Security**: Report security vulnerabilities to [Email](mailto:zenith-sentry@orildo.sbs)

**Note**: Please do not create GitHub issues for bug reports. Use the bug reporting site above.
