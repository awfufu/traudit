# traudit (Traffic Audit)

[English](README.md) | 简体中文

traudit 是一个支持 TCP/UDP/Unix Socket 的反向代理程序，专注于连接审计，支持多种数据库。

## 功能

- **多协议支持**: 支持 TCP, UDP, Unix Domain Socket。
- **Proxy Protocol**: 支持 Proxy Protocol 以记录真实 IP。
- **审计日志**: 将连接信息存入数据库 (ClickHouse, MySQL, PostgreSQL, SQLite)。
- **高性能转发**: 在 Linux 下使用 `splice` 实现零拷贝转发。

什么？你不需要数据库？那你去用 [HAProxy](https://www.haproxy.org/) 吧。

## 配置

请查看 [config_example.yaml](config_example.yaml)。

## TODO List

- [ ] 核心功能
    - [ ] 配置文件解析 (`serde_yaml`)
    - [ ] 监听器抽象 (TCP/UDP/Unix)
    - [ ] Proxy Protocol 解析与处理
    - [ ] 零拷贝转发循环 (`splice`)
- [ ] 数据库
    - [ ] 定义审计日志结构
    - [ ] 实现 `AuditLogger` Trait
    - [ ] ClickHouse 适配器
    - [ ] SQLite/MySQL 适配器
- [ ] 测试
    - [ ] 单元测试 (配置与协议)
    - [ ] 端到端转发测试
- [ ] 文档
    - [ ] 详细配置指南
    - [ ] 部署文档
