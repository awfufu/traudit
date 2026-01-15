# traudit (Traffic Audit)

English | [简体中文](README_cn.md)

traudit is a reverse proxy supporting TCP/UDP/Unix Sockets, focused on connection auditing with support for multiple databases.

## Features

- **Multi-Protocol Support**: TCP, UDP, Unix Domain Sockets.
- **Proxy Protocol**: Support Proxy Protocol to record real IP.
- **Audit Logging**: Store connection information in databases (ClickHouse, MySQL, PostgreSQL, SQLite).
- **Zero-Copy Forwarding**: Uses `splice` on Linux for zero-copy forwarding.

What? You don't need a database? Then go use [HAProxy](https://www.haproxy.org/).

## Configuration

See [config_example.yaml](config_example.yaml).

## TODO List

- [x] Core Implementation
    - [x] Configuration parsing (`serde_yaml`)
    - [x] TCP/UDP/Unix Listener abstraction
    - [x] Proxy Protocol parsing & handling
    - [x] Zero-copy forwarding loop (`splice`)
- [ ] Database Integration
    - [ ] Define Audit Log schema
    - [ ] Implement `AuditLogger` trait
    - [ ] ClickHouse adapter
    - [ ] SQLite/MySQL adapters
- [x] Testing
    - [ ] Unit tests for config & protocol
    - [x] End-to-end forwarding tests
- [ ] Documentation
    - [ ] Detailed configuration guide
    - [ ] Deployment guide
