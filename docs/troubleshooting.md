# Zenith-Sentry Troubleshooting Guide

This guide provides solutions to common issues and frequently asked questions for Zenith-Sentry.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Configuration Issues](#configuration-issues)
- [Database Issues](#database-issues)
- [eBPF Issues](#ebpf-issues)
- [API Issues](#api-issues)
- [Performance Issues](#performance-issues)
- [Security Issues](#security-issues)
- [FAQ](#faq)
- [Getting Help](#getting-help)

## Installation Issues

### Python Version Not Supported

**Problem**: `Python 3.8+ required, found 3.7.x`

**Solution**:
```bash
# Install Python 3.8 or higher
sudo apt-get install python3.8 python3.8-venv

# Create virtual environment
python3.8 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Dependencies Installation Failed

**Problem**: `pip install -r requirements.txt` fails with errors

**Solution**:
```bash
# Upgrade pip
pip install --upgrade pip

# Install system dependencies
sudo apt-get install python3-dev build-essential

# Install dependencies
pip install -r requirements.txt
```

### eBPF Dependencies Missing

**Problem**: `bcc module not found`

**Solution**:
```bash
# Install eBPF dependencies
./install_ebpf_deps.sh

# Or install manually
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)

# Verify installation
python -c "import bcc; print(bcc.__version__)"
```

## Configuration Issues

### Config File Not Found

**Problem**: `Config file not found at config.yaml`

**Solution**:
```bash
# Create config directory
sudo mkdir -p /etc/zenith-sentry

# Copy default config
sudo cp config.yaml /etc/zenith-sentry/

# Or specify config path
zenith-sentry --config /path/to/config.yaml
```

### Invalid Configuration

**Problem**: `Configuration validation failed`

**Solution**:
```bash
# Validate config file
python -c "from zenith.config import ConfigLoader; ConfigLoader('config.yaml')"

# Check config syntax
python -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Review config file for errors
cat config.yaml
```

### Permission Denied on Config File

**Problem**: `Permission denied: /etc/zenith-sentry/config.yaml`

**Solution**:
```bash
# Fix permissions
sudo chown -R zenith-sentry:zenith-sentry /etc/zenith-sentry/
sudo chmod 644 /etc/zenith-sentry/config.yaml

# Or run with sudo
sudo zenith-sentry --config /etc/zenith-sentry/config.yaml
```

## Database Issues

### Database Connection Failed

**Problem**: `Could not connect to database`

**Solution**:
```bash
# Check if PostgreSQL is running
sudo systemctl status postgresql

# Start PostgreSQL
sudo systemctl start postgresql

# Test connection
psql -h localhost -U zenith -d zenith

# Check DATABASE_URL environment variable
echo $DATABASE_URL

# Verify database credentials
sudo -u postgres psql
\l
\du
```

### Database Migration Failed

**Problem**: `Migration failed: relation already exists`

**Solution**:
```bash
# Check current migration status
python -m zenith.db.migrations current

# Rollback migration
python -m zenith.db.migrations downgrade

# Reset database (WARNING: deletes all data)
python -m zenith.db.migrations reset

# Re-run migrations
python -m zenith.db.migrations upgrade
```

### Database Locked

**Problem**: `Database is locked` (SQLite)

**Solution**:
```bash
# Check for running processes
ps aux | grep zenith-sentry

# Kill hanging processes
sudo pkill -f zenith-sentry

# Remove lock file
rm /var/lib/zenith-sentry/zenith.db.lock

# Restart service
sudo systemctl restart zenith-sentry
```

### Slow Database Queries

**Problem**: Queries taking too long

**Solution**:
```bash
# Enable query logging
export ZENITH_DB_LOG_QUERIES=true

# Analyze slow queries
python -m zenith.db.analyze_slow_queries

# Add indexes
python -m zenith.db.migrations add_indexes

# Increase connection pool
# In config.yaml:
database:
  pool_size: 20
  max_overflow: 40
```

## eBPF Issues

### eBPF Not Working

**Problem**: `eBPF monitoring disabled`

**Solution**:
```bash
# Check kernel version (must be 4.10+)
uname -r

# Check BCC installation
python -c "import bcc; print(bcc.__version__)"

# Check eBPF source files
ls -la zenith/ebpf/

# Check permissions (need root)
sudo -v

# Enable eBPF in config
# In config.yaml:
ebpf:
  enabled: true
```

### Permission Denied for eBPF

**Problem**: `Operation not permitted` when loading eBPF

**Solution**:
```bash
# Run as root
sudo zenith-sentry --ebpf

# Or add capabilities
sudo setcap CAP_SYS_ADMIN+ep /usr/bin/python3

# Check BPF permissions
ls -la /sys/kernel/debug/tracing/
```

### eBPF Compilation Failed

**Problem**: `BPF program compilation failed`

**Solution**:
```bash
# Install kernel headers
sudo apt-get install linux-headers-$(uname -r)

# Check eBPF source syntax
clang -c zenith/ebpf/execve_monitor.c -o /tmp/test.o

# Verify kernel features
cat /proc/kallsyms | grep bpf
```

## API Issues

### API Not Starting

**Problem**: `API server failed to start`

**Solution**:
```bash
# Check port availability
sudo netstat -tulpn | grep 8000

# Kill process using port
sudo kill -9 $(sudo lsof -t -i:8000)

# Check API logs
tail -f /var/log/zenith-sentry/api.log

# Test API manually
uvicorn zenith.api.main:app --host 0.0.0.0 --port 8000
```

### CORS Errors

**Problem**: `CORS policy error` in browser

**Solution**:
```bash
# Check CORS configuration in zenith/api/main.py
# Ensure allowed_origins includes your frontend URL

# Or disable for testing (not recommended)
# In zenith/api/main.py:
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Authentication Failed

**Problem**: `401 Unauthorized` error

**Solution**:
```bash
# Check JWT secret
echo $ZENITH_JWT_SECRET

# Verify API key
python -c "from zenith.api.auth import verify_api_key; print(verify_api_key('your-key'))"

# Check token expiration
python -c "from jose import jwt; print(jwt.decode('your-token', 'your-secret', algorithms=['HS256']))"

# Generate new API key
python -c "from zenith.api.auth import generate_api_key; print(generate_api_key())"
```

### API Rate Limiting

**Problem**: `429 Too Many Requests`

**Solution**:
```bash
# Check rate limit configuration
# In config.yaml:
api:
  rate_limit:
    enabled: true
    requests_per_minute: 60

# Increase limit or disable for testing
api:
  rate_limit:
    enabled: false
```

## Performance Issues

### High CPU Usage

**Problem**: CPU usage > 90%

**Solution**:
```bash
# Check CPU usage
top -p $(pgrep zenith-sentry)

# Reduce collection interval
# In config.yaml:
collectors:
  processes:
    interval: 120  # increase from 60
  network:
    interval: 60   # increase from 30

# Disable eBPF if not needed
ebpf:
  enabled: false

# Profile the application
python -m cProfile -o profile.stats process_execve_monitor.py
python -m pstats profile.stats
```

### High Memory Usage

**Problem**: Memory usage > 2GB

**Solution**:
```bash
# Check memory usage
ps aux | grep zenith-sentry

# Reduce event buffer size
# In config.yaml:
ebpf:
  max_events: 1000  # reduce from 10000

# Enable data retention
retention:
  findings_days: 30  # reduce from 90
  events_days: 7     # reduce from 30

# Run cleanup manually
python -m zenith.db.retention cleanup
```

### Slow Scan Performance

**Problem**: Scans taking too long

**Solution**:
```bash
# Disable unnecessary collectors
collectors:
  system:
    enabled: false

# Reduce scope
detectors:
  process_detector:
    enabled: true
  network_detector:
    enabled: false

# Use quick scan mode
zenith-sentry quick-scan
```

## Security Issues

### Permission Denied

**Problem**: `Permission denied` on files

**Solution**:
```bash
# Check file permissions
ls -la /etc/zenith-sentry/
ls -la /var/log/zenith-sentry/

# Fix permissions
sudo chown -R zenith-sentry:zenith-sentry /etc/zenith-sentry/
sudo chown -R zenith-sentry:zenith-sentry /var/log/zenith-sentry/
sudo chmod 750 /etc/zenith-sentry/
sudo chmod 750 /var/log/zenith-sentry/
```

### Encryption Key Missing

**Problem**: `ZENITH_ENCRYPTION_KEY not set`

**Solution**:
```bash
# Generate encryption key
python -c "from zenith.security.encryption import generate_key; print(generate_key())"

# Set environment variable
export ZENITH_ENCRYPTION_KEY="your-generated-key"

# Or add to systemd service
sudo systemctl edit zenith-sentry
# Add:
[Service]
Environment="ZENITH_ENCRYPTION_KEY=your-generated-key"

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart zenith-sentry
```

### Security Alerts Not Sending

**Problem**: Email alerts not received

**Solution**:
```bash
# Check SMTP configuration
# In config.yaml:
alerts:
  smtp_host: "smtp.example.com"
  smtp_port: 587
  smtp_username: "alerts@example.com"
  smtp_password: "password"

# Test SMTP connection
python -c "
import smtplib
server = smtplib.SMTP('smtp.example.com', 587)
server.starttls()
server.login('alerts@example.com', 'password')
server.quit()
print('SMTP OK')
"

# Check alert severity threshold
alerts:
  severity_threshold: "high"  # only send high+ severity
```

## FAQ

### Q: How do I upgrade Zenith-Sentry?

**A**:
```bash
# Backup database
python zenith/scripts/backup.py

# Pull latest version
git pull origin main

# Update dependencies
pip install --upgrade -r requirements.txt

# Run migrations
python -m zenith.db.migrations upgrade

# Restart service
sudo systemctl restart zenith-sentry
```

### Q: Can I run Zenith-Sentry without root privileges?

**A**: Some features require root privileges:
- eBPF monitoring requires `CAP_SYS_ADMIN`
- Network blocking requires `CAP_NET_ADMIN`
- Process termination requires `CAP_KILL`

You can run without these features as a non-root user, but functionality will be limited.

### Q: How do I disable specific detectors?

**A**: Edit `config.yaml`:
```yaml
detectors:
  process_detector:
    enabled: false
  network_detector:
    enabled: true
```

### Q: How do I export findings to CSV?

**A**:
```bash
# Use API
curl http://localhost:8000/api/v1/findings -H "Authorization: Bearer YOUR_TOKEN" > findings.json

# Or use CLI
zenith-sentry export-findings --format csv --output findings.csv
```

### Q: How do I restore from backup?

**A**:
```bash
# Restore database
python zenith/scripts/restore.py --input /backup/zenith-backup-20240101.db

# Verify restore
python -m zenith.db.base verify
```

### Q: How do I check system health?

**A**:
```bash
# Run health check
curl http://localhost:8000/health

# Or use CLI
zenith-sentry status

# Run verification script
python zenith/scripts/verify_install.py
```

### Q: How do I configure custom alert rules?

**A**: Edit `config.yaml`:
```yaml
alerts:
  rules:
    - name: "Critical Process"
      condition: "risk_level == 'critical' and module == 'process_detector'"
      enabled: true
```

### Q: How do I integrate with SIEM?

**A**: Use the API to send findings to your SIEM:
```bash
# Send to Splunk
curl http://localhost:8000/api/v1/findings | curl -X POST http://splunk-server:8088/services/collector/event -H "Authorization: Splunk YOUR_TOKEN" -d @-

# Send to ELK
curl http://localhost:8000/api/v1/findings | curl -X POST http://elk-server:9200/zenith-findings/_bulk --data-binary @-
```

### Q: How do I monitor Zenith-Sentry?

**A**:
```bash
# Use Prometheus metrics
curl http://localhost:8000/metrics

# Configure Prometheus to scrape metrics
# Add to prometheus.yml:
scrape_configs:
  - job_name: 'zenith-sentry'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
```

### Q: How do I troubleshoot eBPF issues?

**A**:
```bash
# Check kernel version
uname -r

# Check BCC installation
python -c "import bcc; print(bcc.__version__)"

# Check eBPF features
cat /proc/kallsyms | grep bpf

# Test with simple BPF program
python -c "
from bcc import BPF
bpf = BPF(text='int kprobe__do_sys_open(void *ctx) { return 0; }')
print('eBPF OK')
"
```

### Q: How do I disable logging?

**A**: Edit `config.yaml`:
```yaml
logging:
  level: "ERROR"  # Only log errors
  file: "/dev/null"  # Disable file logging
```

### Q: How do I run Zenith-Sentry in development mode?

**A**:
```bash
# Run with hot reload
uvicorn zenith.api.main:app --reload --host 0.0.0.0 --port 8000

# Run web UI in development
cd web
npm run dev
```

### Q: How do I report a bug?

**A**: 
1. Check existing issues on GitHub
2. Create a new issue with:
   - Zenith-Sentry version
   - OS and kernel version
   - Error logs
   - Steps to reproduce

### Q: How do I contribute?

**A**: 
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Getting Help

If you're still experiencing issues:

1. Check the [GitHub Issues](https://github.com/yourusername/Zenith-Sentry/issues)
2. Review the [Documentation](https://github.com/yourusername/Zenith-Sentry/tree/main/docs)
3. Join the [Discord/Slack community](https://discord.gg/zenith-sentry)
4. Contact support at support@zenith-sentry.com
