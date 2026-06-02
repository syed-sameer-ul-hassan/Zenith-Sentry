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

```mermaid
flowchart TB
    subgraph DC["DATA COLLECTION LAYER"]
        PC["Process Collector"]
        NC["Network Collector"]
        SC["System Collector"]
        EM["eBPF Monitor"]
    end

    subgraph DL["DETECTION LAYER"]
        PD["Process Detector"]
        ND["Network Detector"]
        SD["System Detector"]
        ED["eBPF Execution Detector"]
    end

    subgraph RL["RESPONSE LAYER"]
        ME["Mitigation Engine"]
        IB["IP Blocking"]
        PT["Process Termination"]
    end

    subgraph SL["STORAGE LAYER"]
        DB["SQLite / PostgreSQL"]
        EL["Event Logs"]
        AL["Audit Logs"]
    end

    subgraph AL2["API LAYER"]
        FS["FastAPI Server"]
        RE["REST Endpoints"]
    end

    subgraph PL["PRESENTATION LAYER"]
        CLI["CLI Interface"]
        TUI["TUI Interface"]
    end

    PC --> PD
    NC --> ND
    SC --> SD
    EM --> ED
    PD --> ME
    ND --> ME
    SD --> ME
    ED --> ME
    ME --> IB
    ME --> PT
    ME --> DB
    ME --> EL
    ME --> AL
    RE --> CLI
    RE --> TUI
    FS --> RE
    DB --> RE
```

## Component Architecture

### Core Components

1. **ZenithEngine** - Main orchestration engine that coordinates all components
2. **Collectors** - Gather telemetry data from the system
3. **Detectors** - Analyze telemetry for security threats
4. **Mitigation Engine** - Execute automated response actions

### Data Flow

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant CLI as CLI
    participant E as ZenithEngine
    participant C as Collectors
    participant D as Detectors
    participant S as ScoringEngine
    participant DB as Database
    participant API as REST API

    U->>CLI: Execute scan command
    CLI->>E: Start scan
    E->>C: Collect telemetry
    C-->>E: Return processes, network, files
    E->>D: Inject telemetry
    D-->>E: Return findings
    E->>S: Score findings
    S-->>E: Risk score
    E->>DB: Persist findings
    E-->>CLI: JSON report / TUI alert
    U->>API: Query findings
    API->>DB: Fetch data
    DB-->>API: Return findings
    API-->>U: API response
```

### Module Structure

```mermaid
mindmap
  root((zenith))
    api
      main.py[FastAPI App]
      auth.py[JWT/API Keys]
      models.py[Pydantic Models]
      routes[API Endpoints]
    cli
      main.py[CLI Commands]
    config
      paths.py[FHS/XDG Paths]
      config.py[Config Loader]
    db
      base.py[SQLAlchemy]
      models.py[ORM Models]
      repository.py[Queries]
      retention.py[Data Cleanup]
    ebpf
      execve_monitor.c[eBPF C Program]
      EBPF_GUIDE.md[eBPF Guide]
    monitoring
      metrics.py[Prometheus]
      health.py[Health Checks]
      alerts.py[Email Alerts]
    plugins
      base.py[Plugin Base]
      detectors.py[Built-in]
      ebpf_detector.py[eBPF Events]
    scripts
      backup.py[DB Backup]
      restore.py[DB Restore]
      verify_install.py[Verify]
    security
      encryption.py[AES/PBKDF2]
      event_logger.py[Events]
    utils
      validation.py[Input Val]
      logging.py[Log Sanitize]
      signals.py[Signal Handlers]
    collectors.py[Telemetry]
    engine.py[Orchestrator]
    registry.py[Plugin Loader]
    utils.py[Shared Utils]
```

### Database Schema

```mermaid
erDiagram
    USER ||--o{ SCAN : performs
    USER ||--o{ API_KEY : owns
    SCAN ||--o{ FINDING : contains
    SCAN ||--o{ SYSTEM_EVENT : generates

    USER {
        string id PK
        string username
        string email
        string role
        datetime created_at
        datetime last_login
    }

    API_KEY {
        string id PK
        string user_id FK
        string key_hash
        string name
        boolean is_active
        datetime expires_at
        datetime created_at
        datetime last_used
    }

    SCAN {
        string id PK
        string user_id FK
        string scan_type
        string status
        datetime start_time
        datetime end_time
        boolean ebpf_enabled
        boolean mitigation_enabled
        json target_dirs
        json summary
    }

    FINDING {
        string id PK
        string scan_id FK
        string module
        string risk
        string severity
        string tactic
        text description
        json evidence
        datetime timestamp
        boolean resolved
        datetime resolved_at
    }

    SYSTEM_EVENT {
        int id PK
        string event_type
        string source
        text message
        string severity
        json metadata
        datetime timestamp
    }
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

```mermaid
flowchart LR
    A["Attacker"]
    V["Vulnerability"]
    DL["Detection Layer"]
    ST["Security Team"]
    ME["Mitigation Engine"]
    BT["Block Threat"]
    LA["Log Audit Trail"]
    CP["Compliance"]

    A --> V
    V --> DL
    DL --> ST
    DL --> ME
    ME --> BT
    ME --> LA
    LA --> CP
```

## Deployment Architecture

### Single-Node Deployment

```mermaid
flowchart TB
    subgraph Host["Linux Host"]
        ZC["Zenith-Sentry Core"]
        DB["SQLite Database"]
        LF["Log Files"]
        CFG["Configuration"]
    end

    ZC --> DB
    ZC --> LF
    ZC --> CFG
```

### Distributed Deployment

```mermaid
flowchart TB
    LB["Load Balancer (Nginx/HAProxy)"]

    subgraph AppTier["Application Tier"]
        A1["API Server 1"]
        A2["API Server 2"]
        A3["API Server 3"]
    end

    subgraph DataTier["Data Tier"]
        PP["PostgreSQL Primary"]
        PR["PostgreSQL Replica"]
    end

    subgraph MonitorTier["Monitoring Tier"]
        PM["Prometheus"]
        GF["Grafana"]
    end

    LB --> A1
    LB --> A2
    LB --> A3
    A1 --> PP
    A2 --> PP
    A3 --> PP
    PP --> PR
    PM --> A1
    PM --> A2
    PM --> A3
    PM --> GF
```

## Performance Considerations

- **Memory Management**: Circular buffer for eBPF events to prevent memory leaks
- **Database Indexing**: Indexed queries for fast lookups
- **Connection Pooling**: SQLAlchemy connection pooling for database efficiency
- **Async Processing**: FastAPI async support for concurrent requests
- **Data Retention**: Automatic cleanup of old data to prevent database bloat

## Class Diagram

```mermaid
classDiagram
    class ZenithEngine {
        +ConfigLoader config
        +PluginRegistry registry
        +start_ebpf_monitor()
        +stop_ebpf_monitor()
        +run_scan()
        -_collect_telemetry()
        -_print_human_readable()
    }
    class PluginRegistry {
        +load_plugins()
        +instantiate(**kwargs)
        -_load_plugin_file()
        -_scan_plugins()
    }
    class ProcessCollector {
        +collect() dict
    }
    class NetworkCollector {
        +collect() list
    }
    class SystemCollector {
        +scan_dirs list
        +collect() dict
    }
    class ProcessExecutionMonitor {
        +ebpf_source str
        +safe_mode bool
        +run()
        -_load_ebpf()
        -_handle_execve_event()
        -_handle_connect_event()
    }
    ZenithEngine --> PluginRegistry : uses
    ZenithEngine --> ProcessCollector : collects
    ZenithEngine --> NetworkCollector : collects
    ZenithEngine --> SystemCollector : collects
    ZenithEngine --> ProcessExecutionMonitor : monitors
```

## User Journey

```mermaid
journey
    title Operator Workflow with Zenith-Sentry
    section Installation
      Run install.sh: 5: Operator
      Verify deps: 4: Operator
    section Scanning
      Start scan: 5: Operator
      Wait for results: 3: Operator
    section Analysis
      Review findings: 4: Analyst
      Score risks: 4: Analyst
    section Response
      Trigger mitigation: 5: SOC
      Block IPs: 5: SOC
      Kill processes: 4: SOC
    section Reporting
      Export JSON: 4: Analyst
      Archive logs: 3: Analyst
```
