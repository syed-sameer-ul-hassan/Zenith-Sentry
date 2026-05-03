# Zenith-Sentry Architecture

This document provides a comprehensive overview of the Zenith-Sentry system architecture, including component design, data flow, and deployment patterns.

## Table of Contents

- [System Overview](#system-overview)
- [Component Architecture](#component-architecture)
- [Data Flow](#data-flow)
- [Module Structure](#module-structure)
- [Database Schema](#database-schema)
- [Security Architecture](#security-architecture)
- [Deployment Architecture](#deployment-architecture)
- [Performance Considerations](#performance-considerations)

## System Overview

Zenith-Sentry is a Linux Endpoint Detection and Response (EDR) tool that provides real-time security monitoring, threat detection, and automated response capabilities. The system is built with a modular, event-driven architecture that ensures high performance and scalability.

### Key Design Principles

- **Defense in Depth**: Multiple layers of security controls
- **Behavioral Analysis**: Focus on behavior patterns rather than static signatures
- **Kernel-Level Visibility**: eBPF monitoring for tamper-proof telemetry
- **Modular Architecture**: Plugin-based detection system
- **Production Ready**: Built for reliability and scalability

### System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  DATA COLLECTION LAYER                          │
└─────────────────────────────────────────────────────────────────┘
  ┌───────────────── ┐      ┌─────────────────┐      ┌─────────────────┐
  │ Process Collector│────▶ │Network Collector│────▶ │ System Collector│
  └───────────────── ┘      └─────────────────┘      └─────────────────┘
                                                               │
                                                               ▼
                                                      ┌─────────────────┐
                                                      │   eBPF Monitor  │
                                                      └─────────────────┘
                                                               │
                                                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    DETECTION LAYER                              │
└─────────────────────────────────────────────────────────────────┘
  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
  │Process Detector │  │Network Detector │  │System Detector  │
  └─────────────────┘  └─────────────────┘  └─────────────────┘
                                                               │
                                                               ▼
                                                ┌─────────────────────────┐
                                                │eBPF Execution Detector  │
                                                └─────────────────────────┘
                                                               │
                                                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    RESPONSE LAYER                               │
└─────────────────────────────────────────────────────────────────┘
  ┌───────────────── ┐      ┌─────────────────┐      ┌────────────────  ─┐
  │Mitigation Engine │────▶ │   IP Blocking   │────▶ │Process Termination│
  └───────────────── ┘      └─────────────────┘      └────────────────  ─┘
                                                               │
                                                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    STORAGE LAYER                                │
└─────────────────────────────────────────────────────────────────┘
  ┌───────────────── ┐  ┌─────────────────┐  ┌─────────────────┐
  │SQLite/PostgreSQL │  │   Event Logs    │  │   Audit Logs    │
  └───────────────── ┘  └─────────────────┘  └─────────────────┘
                                                               │
                                                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                      API LAYER                                  │
└─────────────────────────────────────────────────────────────────┘
  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
  │  FastAPI Server │────▶│ REST Endpoints  │────▶│   WebSocket     │
  └─────────────────┘     └─────────────────┘     └─────────────────┘
                                                               │
                                                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                  PRESENTATION LAYER                             │
└─────────────────────────────────────────────────────────────────┘
  ┌─────────────────┐      ┌─────────────────┐
  │     Web UI      │      │  CLI Interface  │
  └─────────────────┘      └─────────────────┘
```

## Component Architecture

### Core Components

1. **ZenithEngine** - Main orchestration engine that coordinates all components
2. **Collectors** - Gather telemetry data from the system
3. **Detectors** - Analyze telemetry for security threats
4. **Mitigation Engine** - Execute automated response actions

### Data Flow

```
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌──────────┐     ┌──────────┐
│  User   │────▶│   CLI   │────▶│ Engine  │────▶│Collector │────▶│Telemetry │
└─────────┘     └─────────┘     └─────────┘     └──────────┘     └──────────┘
                                              │
                                              ▼
                                      ┌──────────────────┐
                                      │    Detectors     │
                                      └────────┬─────────┘
                                               │
                                               ▼
                                      ┌──────────────────┐
                                      │     Findings     │
                                      └────────┬─────────┘
                                               │
                                               ▼
                                      ┌──────────────────┐
                                      │    Database      │────▶ Storage
                                      └────────┬─────────┘
                                               │
                                               ▼
                                      ┌──────────────────┐
                                      │      API         │◀──── User
                                      └──────────────────┘
```

### Module Structure

```
zenith/
├── api/                 # REST API layer
│   ├── main.py         # FastAPI application
│   ├── auth.py         # Authentication (JWT, API keys)
│   ├── models.py       # Pydantic models
│   └── routes/         # API endpoints
├── cli/                 # Command-line interface
│   └── main.py         # CLI commands
├── config/              # Configuration management
│   └── paths.py        # Path management (FHS/XDG)
├── db/                  # Database layer
│   ├── base.py         # SQLAlchemy setup
│   ├── models.py       # ORM models
│   ├── repository.py   # Query interface
│   └── retention.py    # Data retention
├── ebpf/                # eBPF kernel monitoring
│   ├── execve_monitor.c # eBPF C program
│   └── EBPF_GUIDE.md   # eBPF implementation guide
├── monitoring/          # Monitoring & metrics
│   ├── metrics.py      # Prometheus metrics
│   ├── health.py       # Health checks
│   └── alerts.py       # Email alerting
├── plugins/             # Plugin system
│   ├── base.py         # Plugin base classes
│   ├── detectors.py    # Built-in detectors
│   └── ebpf_detector.py # eBPF event processor
├── scripts/             # Utility scripts
│   ├── backup.py       # Database backup
│   ├── restore.py      # Database restore
│   └── verify_install.py # Installation verification
├── security/            # Security utilities
│   ├── encryption.py   # Encryption utilities
│   └── event_logger.py # Security event logging
├── utils/               # Utility functions
│   ├── validation.py   # Input validation
│   ├── logging.py      # Logging utilities
│   └── signals.py      # Signal handling
├── collectors.py        # Telemetry collectors
├── config.py           # Configuration loader
├── core.py             # Core interfaces (IDetector)
├── engine.py           # Main orchestration engine
├── registry.py         # Plugin discovery & loading
└── utils.py            # Shared utilities
```

### Database Schema

```
┌─────────────────────────────────────────────────────────────────────┐
│                          ORGANIZATION                               │
└─────────────────────────────────────────────────────────────────────┘
  ┌─────────────────────────────────────────────────────────────┐
  │ uuid PK  name  slug  created_at                             │
  └─────────────────────────────────────────────────────────────┘
                                                               │
                                                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                               USER                                  │
└─────────────────────────────────────────────────────────────────────┘
  ┌─────────────────────────────────────────────────────────────┐
  │ uuid PK  username  email  role  created_at                  │
  └─────────────────────────────────────────────────────────────┘
           │                                    │
           ▼                                    ▼
  ┌─────────────────────┐          ┌─────────────────────┐
  │       SCAN          │          │      API_KEY        │
  ├─────────────────────┤          ├─────────────────────┤
  │ uuid PK             │          │ uuid PK             │
  │ user_id FK          │          │ user_id FK          │
  │ scan_type           │          │ key_hash            │
  │ status              │          │ name                │
  │ started_at          │          │ created_at          │
  │ completed_at        │          │ expires_at          │
  └─────────────────────┘          └─────────────────────┘
           │
           ▼
  ┌─────────────────────┐
  │      FINDING        │
  ├─────────────────────┤
  │ uuid PK             │
  │ scan_id FK          │
  │ risk_level          │
  │ severity            │
  │ module              │
  │ title               │
  │ description         │
  │ timestamp           │
  └─────────────────────┘
           │
           ▼
  ┌─────────────────────┐
  │   SYSTEM_EVENT      │
  ├─────────────────────┤
  │ uuid PK             │
  │ scan_id FK          │
  │ event_type          │
  │ severity            │
  │ message             │
  │ timestamp           │
  └─────────────────────┘
```

## Security Architecture

### Defense in Depth

1. **Input Validation** - All inputs validated before processing
2. **Command Injection Prevention** - Parameterized commands, IP whitelisting
3. **Secure Signal Handling** - Safe signal handlers with proper cleanup
4. **Encryption at Rest** - AES-256 encryption for sensitive data
5. **Secure Logging** - PII redaction, security event correlation
6. **Authentication** - JWT tokens and API key authentication
7. **Authorization** - Role-based access control (RBAC)

### Threat Model

```
┌─────────┐     ┌──────────────┐      ┌──────────────────┐
│Attacker │────▶│ Vulnerability│────▶ │ Detection Layer  │
└─────────┘     └──────────────┘      └──────────────────┘
                                           │
                          ┌────────────────┴────────────────┐
                          │                                 │
                          ▼                                 ▼
                   ┌──────────────┐                 ┌──────────────┐
                   │Security Team │                 │Mitigation    │
                   └──────────────┘                 │ Engine       │
                                                    └──────────────┘
                                                          │
                                          ┌───────────────┴───────────────┐
                                          │                               │
                                          ▼                               ▼
                                   ┌──────────────┐              ┌──────────────┐
                                   │   Block      │              │     Log      │
                                   │   Threat     │              │ Audit Trail  │
                                   └──────────────┘              └──────────────┘
                                                                         │
                                                                         ▼
                                                                   ┌──────────────┐
                                                                   │ Compliance   │
                                                                   └──────────────┘
```

## Deployment Architecture

### Single-Node Deployment

```
┌─────────────────────────────────────────────────────────────────┐
│                        Linux Host                               │
└─────────────────────────────────────────────────────────────────┘
  ┌─────────────────────────────────────────────────────────────┐
  │              Zenith-Sentry Core                             │
  └─────────────────────────────────────────────────────────────┘
                           │
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                  SQLite Database                            │
  └─────────────────────────────────────────────────────────────┘
                           │
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                    Log Files                                │
  └─────────────────────────────────────────────────────────────┘
                           │
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                   Configuration                             │
  └─────────────────────────────────────────────────────────────┘
```

### Distributed Deployment

```
┌─────────────────────────────────────────────────────────────────┐
│                    Load Balancer                                │
│                     Nginx/HAProxy                               │
└─────────────────────────────────────────────────────────────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
  │ API Server 1  │  │ API Server 2  │  │ API Server 3  │
  └───────────────┘  └───────────────┘  └───────────────┘
          │                  │                  │
          └──────────────────┼──────────────────┘
                             ▼
  ┌─────────────────────────────────────────────────────────────┐
  │              PostgreSQL Primary                             │
  └─────────────────────────────────────────────────────────────┘
                           │
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │              PostgreSQL Replica                             │
  └─────────────────────────────────────────────────────────────┘
          │                  │
          ▼                  ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  Prometheus  ───────▶  Grafana                              │
  └─────────────────────────────────────────────────────────────┘
```

## Performance Considerations

- **Memory Management**: Circular buffer for eBPF events to prevent memory leaks
- **Database Indexing**: Indexed queries for fast lookups
- **Connection Pooling**: SQLAlchemy connection pooling for database efficiency
- **Async Processing**: FastAPI async support for concurrent requests
- **Data Retention**: Automatic cleanup of old data to prevent database bloat
