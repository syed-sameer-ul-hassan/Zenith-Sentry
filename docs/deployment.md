# Zenith-Sentry Deployment Guide

This guide covers deploying Zenith-Sentry in various environments, including Docker and Kubernetes.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Systemd Service](#systemd-service)
- [Configuration](#configuration)
- [Database Setup](#database-setup)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+, RHEL 8+)
- **Python**: 3.8 or higher
- **Memory**: 4GB minimum, 8GB recommended
- **Disk**: 20GB minimum for logs and database
- **CPU**: 2 cores minimum, 4 cores recommended

### Optional Requirements

- **eBPF Support**: Linux kernel 4.10+ for eBPF monitoring
- **PostgreSQL**: For production database (recommended)
- **Docker**: For containerized deployment
- **Kubernetes**: For orchestration

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/syed-sameer-ul-hassan/Zenith-Sentry.git
cd Zenith-Sentry

# Install dependencies
pip install -r requirements.txt

# Install eBPF dependencies (optional, for eBPF monitoring)
./install_ebpf_deps.sh

# Verify installation
python zenith/scripts/verify_install.py
```

### Using pip

```bash
pip install zenith-sentry
```

## Docker Deployment

### Build Docker Image

```bash
# Build the image
docker build -t zenith-sentry:latest .

# Or build with specific version
docker build -t zenith-sentry:0.1.0 .
```

### Run Docker Container

```bash
# Basic run
docker run -d \
  --name zenith-sentry \
  -v /var/log/zenith-sentry:/var/log/zenith-sentry \
  -v /etc/zenith-sentry:/etc/zenith-sentry \
  -p 8000:8000 \
  zenith-sentry:latest

# Run with PostgreSQL
docker run -d \
  --name zenith-sentry \
  --link postgres:postgres \
  -e DATABASE_URL=postgresql://zenith:password@postgres:5432/zenith \
  -v /var/log/zenith-sentry:/var/log/zenith-sentry \
  -v /etc/zenith-sentry:/etc/zenith-sentry \
  -p 8000:8000 \
  zenith-sentry:latest

# Run with eBPF support (privileged mode)
docker run -d \
  --name zenith-sentry \
  --privileged \
  --network host \
  -v /var/log/zenith-sentry:/var/log/zenith-sentry \
  -v /etc/zenith-sentry:/etc/zenith-sentry \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /lib/modules:/lib/modules:ro \
  zenith-sentry:latest
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  zenith-sentry:
    build: .
    container_name: zenith-sentry
    ports:
      - "8000:8000"
    volumes:
      - /var/log/zenith-sentry:/var/log/zenith-sentry
      - /etc/zenith-sentry:/etc/zenith-sentry
      - ./config.yaml:/etc/zenith-sentry/config.yaml:ro
    environment:
      - DATABASE_URL=postgresql://zenith:password@postgres:5432/zenith
      - ZENITH_ENCRYPTION_KEY=your-encryption-key
    depends_on:
      - postgres
    restart: unless-stopped

  postgres:
    image: postgres:14
    container_name: zenith-postgres
    environment:
      - POSTGRES_DB=zenith
      - POSTGRES_USER=zenith
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres-data:/var/lib/postgresql/data
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    container_name: zenith-prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: zenith-grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana
    restart: unless-stopped

volumes:
  postgres-data:
  prometheus-data:
  grafana-data:
```

Run with Docker Compose:

```bash
docker-compose up -d
```

## Kubernetes Deployment

### Create Namespace

```bash
kubectl create namespace zenith-sentry
```

### Create ConfigMap

Create `k8s-configmap.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: zenith-sentry-config
  namespace: zenith-sentry
data:
  config.yaml: |
    # Your configuration here
    version: "1.0"
    collectors:
      processes:
        enabled: true
      network:
        enabled: true
      system:
        enabled: true
    detectors:
      process_detector:
        enabled: true
      network_detector:
        enabled: true
```

Apply ConfigMap:

```bash
kubectl apply -f k8s-configmap.yaml
```

### Create Secret

```bash
kubectl create secret generic zenith-sentry-secrets \
  --from-literal=database-url="postgresql://zenith:password@postgres:5432/zenith" \
  --from-literal=encryption-key="your-encryption-key" \
  --namespace=zenith-sentry
```

### Create Deployment

Create `k8s-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zenith-sentry
  namespace: zenith-sentry
spec:
  replicas: 3
  selector:
    matchLabels:
      app: zenith-sentry
  template:
    metadata:
      labels:
        app: zenith-sentry
    spec:
      containers:
      - name: zenith-sentry
        image: zenith-sentry:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: zenith-sentry-secrets
              key: database-url
        - name: ZENITH_ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: zenith-sentry-secrets
              key: encryption-key
        volumeMounts:
        - name: config
          mountPath: /etc/zenith-sentry
        - name: logs
          mountPath: /var/log/zenith-sentry
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: zenith-sentry-config
      - name: logs
        emptyDir: {}
```

Apply Deployment:

```bash
kubectl apply -f k8s-deployment.yaml
```

### Create Service

Create `k8s-service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: zenith-sentry
  namespace: zenith-sentry
spec:
  selector:
    app: zenith-sentry
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer
```

Apply Service:

```bash
kubectl apply -f k8s-service.yaml
```

### Create Ingress (Optional)

Create `k8s-ingress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: zenith-sentry
  namespace: zenith-sentry
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - zenith-sentry.example.com
    secretName: zenith-sentry-tls
  rules:
  - host: zenith-sentry.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: zenith-sentry
            port:
              number: 80
```

Apply Ingress:

```bash
kubectl apply -f k8s-ingress.yaml
```

## Systemd Service

### Install Service File

```bash
# Copy service file
sudo cp zenith-sentry.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable zenith-sentry

# Start service
sudo systemctl start zenith-sentry

# Check status
sudo systemctl status zenith-sentry
```

### Service Configuration

The systemd service includes security hardening:
- `NoNewPrivileges`: Prevents privilege escalation
- `PrivateTmp`: Isolates /tmp directory
- `ReadWritePaths`: Limits writable paths
- `CapabilityBoundingSet`: Drops unnecessary capabilities
- `ProtectSystem`: Protects system directories

## Configuration

### Environment Variables

```bash
# Database configuration
export DATABASE_URL="postgresql://zenith:password@localhost:5432/zenith"

# Encryption key (required)
export ZENITH_ENCRYPTION_KEY="your-encryption-key-here"

# API configuration
export API_HOST="0.0.0.0"
export API_PORT="8000"

# Log level
export LOG_LEVEL="INFO"

# Enable eBPF monitoring
export EBPF_ENABLED="true"
```

### Configuration File

Create `/etc/zenith-sentry/config.yaml`:

```yaml
version: "1.0"

# Collectors configuration
collectors:
  processes:
    enabled: true
    interval: 60
  network:
    enabled: true
    interval: 30
  system:
    enabled: true
    interval: 300

# Detectors configuration
detectors:
  process_detector:
    enabled: true
    suspicious_ports: [4444, 5555, 6666]
    critical_binaries: ["/bin/sh", "/bin/bash", "/usr/bin/python3"]
  network_detector:
    enabled: true
    blocked_ips: []
    allowed_ips: ["192.168.1.0/24"]

# Database configuration
database:
  url: "postgresql://zenith:password@localhost:5432/zenith"
  pool_size: 10
  max_overflow: 20

# Retention configuration
retention:
  findings_days: 90
  events_days: 30
  scans_days: 365

# Alert configuration
alerts:
  enabled: true
  smtp_host: "smtp.example.com"
  smtp_port: 587
  smtp_username: "alerts@example.com"
  smtp_password: "password"
  recipients: ["security@example.com"]
  severity_threshold: "high"
```

## Database Setup

### PostgreSQL Setup

```bash
# Install PostgreSQL
sudo apt-get install postgresql postgresql-contrib

# Create database
sudo -u postgres psql
CREATE DATABASE zenith;
CREATE USER zenith WITH PASSWORD 'password';
GRANT ALL PRIVILEGES ON DATABASE zenith TO zenith;
\q

# Run migrations
python -m zenith.db.migrations upgrade
```

### SQLite Setup (Development)

```bash
# SQLite is used by default
# Database will be created at /var/lib/zenith-sentry/zenith.db

# Initialize database
python -m zenith.db.base create_tables
```

## Monitoring

### Prometheus Configuration

Create `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'zenith-sentry'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
```

### Health Checks

```bash
# Liveness check
curl http://localhost:8000/health/live

# Readiness check
curl http://localhost:8000/health/ready

# Full health check
curl http://localhost:8000/health
```

### Log Monitoring

```bash
# View logs
sudo journalctl -u zenith-sentry -f

# View application logs
tail -f /var/log/zenith-sentry/zenith-sentry.log
```

## Troubleshooting

### Common Issues

1. **Service won't start**
   ```bash
   # Check service status
   sudo systemctl status zenith-sentry
   
   # View logs
   sudo journalctl -u zenith-sentry -n 50
   ```

2. **Database connection failed**
   ```bash
   # Verify database is running
   sudo systemctl status postgresql
   
   # Test connection
   psql -h localhost -U zenith -d zenith
   ```

3. **eBPF monitoring not working**
   ```bash
   # Check kernel version
   uname -r
   
   # Verify BCC is installed
   python -c "import bcc; print(bcc.__version__)"
   
   # Check permissions
   sudo -v
   ```

4. **Permission denied errors**
   ```bash
   # Check file permissions
   ls -la /etc/zenith-sentry/
   ls -la /var/log/zenith-sentry/
   
   # Fix permissions
   sudo chown -R zenith-sentry:zenith-sentry /etc/zenith-sentry/
   sudo chown -R zenith-sentry:zenith-sentry /var/log/zenith-sentry/
   ```

### Performance Tuning

1. **Increase database pool size**
   ```yaml
   database:
     pool_size: 20
     max_overflow: 40
   ```

2. **Adjust retention policies**
   ```yaml
   retention:
     findings_days: 30
     events_days: 7
   ```

3. **Enable connection pooling**
   ```bash
   pip install SQLAlchemy[pool]
   ```

### Backup and Restore

```bash
# Backup database
python zenith/scripts/backup.py --output /backup/zenith-backup-$(date +%Y%m%d).db

# Restore database
python zenith/scripts/restore.py --input /backup/zenith-backup-20240101.db
```

## Security Considerations

1. **Run as non-root user**
   ```bash
   sudo useradd -r -s /bin/false zenith-sentry
   sudo chown -R zenith-sentry:zenith-sentry /etc/zenith-sentry/
   sudo chown -R zenith-sentry:zenith-sentry /var/log/zenith-sentry/
   ```

2. **Use TLS in production**
   ```yaml
   # Configure nginx reverse proxy with TLS
   server {
       listen 443 ssl;
       server_name zenith-sentry.example.com;
       
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;
       
       location / {
           proxy_pass http://localhost:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

3. **Configure firewall**
   ```bash
   # Allow only necessary ports
   sudo ufw allow 8000/tcp
   sudo ufw enable
   ```

4. **Regular security updates**
   ```bash
   # Update system packages
   sudo apt-get update && sudo apt-get upgrade
   
   # Update Python dependencies
   pip install --upgrade -r requirements.txt
   ```
