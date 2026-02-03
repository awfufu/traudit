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

- [x] 核心功能
    - [x] 配置文件解析 (`serde_yaml`)
    - [x] TCP 代理与零拷贝转发 (`splice`)
    - [x] Proxy Protocol V1/V2 解析
    - [ ] UDP 转发 (计划中)
    - [x] Unix Socket 转发
- [x] 数据库集成
    - [x] ClickHouse 适配器 (原生接口)
    - [x] 流量统计 (字节数)
    - [x] IPv6 支持
    - [ ] SQLite/MySQL 适配器 (计划中)
- [ ] 文档与测试
    - [x] 基础端到端测试
    - [x] 单元测试
    - [ ] 部署文档
