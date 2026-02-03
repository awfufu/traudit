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
    - [x] TCP Proxy & Zero-copy forwarding (`splice`)
    - [x] Proxy Protocol V1/V2 parsing
    - [ ] UDP Forwarding (Planned)
    - [x] Unix Socket Forwarding
- [x] Database Integration
    - [x] ClickHouse Adapter (Native Interface)
    - [x] Traffic Accounting (Bytes/Bandwidth)
    - [x] IPv6 Support
    - [ ] SQLite/MySQL Adapters (Future)
- [ ] Documentation & Testing
    - [x] Basic End-to-end tests
    - [x] Comprehensive Unit Tests
    - [ ] Deployment Guide
