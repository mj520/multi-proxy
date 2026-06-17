# multi-proxy

轻量多通道代理工具，统一 HTTP 路径入口，支持 HTTP / SOCKS5 / SSH 隧道三类转发通道。

## 功能特性

- 统一 HTTP 路径访问，适配各类客户端
- 支持 HTTP、SOCKS5、SSH 隧道多通道混合配置
- 全链路使用 DSN 格式，配置简洁统一
- 两种调度模式：顺序降级、哈希会话保持
- 定时探活，故障通道自动隔离，恢复后复用
- 完整透传请求方法、Header、Cookie、请求体
- 全通道失效自动直连源站兜底
- 异步架构，高并发、低资源占用

### 安装

```bash
# 开发编译
cargo build
cargo build --release
```

### 访问格式
路径必须以 `/https://` 开头。
```
http://代理IP:端口/https://目标地址
curl http://127.0.0.1:12380/https://ipinfo.io/ip
```

### 通道 DSN 格式
```
http://[账号[:密码]@]主机[:端口]
http://127.0.0.1:1080

socks5://[账号[:密码]@]主机[:端口]
socks5://127.0.0.1:1080

ssh://用户名[:密码]@主机[:端口][?key=私钥路径&keepalive=秒数]
ssh://root:pass@127.0.0.1
ssh://root@host?key=~/.ssh/id_rsa&keepalive=30
参数说明：
- `key`: 本地私钥路径（优先级高于密码），密码和可以同时为空 默认 ~/.ssh/id_rsa 
- `keepalive`: 连接保活时长，默认 30 秒
```

### 配置文件

默认读取 `config.toml`：
参数说明：
- `host`: 监听主机（默认 `127.0.0.1`）
- `port`: 监听端口（默认 `12380`）
- `strategy`: `order` 顺序降级 / `hash` 哈希会话保持
- `probe_interval`: 探活间隔（秒）
- `connect_timeout`: 连接超时（秒）
- `upstreams`: 通道列表，顺序即为优先级

### 命令行参数

```bash
./multi-proxy -c ./config.toml
./multi-proxy \
  --host 0.0.0.0 --port 12380 \
  -s order \
  -u "ssh://root@127.0.0.1"

# 等价写法：通过环境变量（flag 优先级高于环境变量）
HOST=0.0.0.0 PORT=12380 ./multi-proxy -c ./config.toml
```

参数说明：
- `-c`: 指定配置文件
- `--host` / `--port`: 临时修改监听主机/端口（对应环境变量 `HOST`/`PORT`，flag 优先）
- `-s`: 临时修改调度策略
- `-u`: 临时添加上游通道（可多次使用）

## 调度与降级逻辑

### 顺序模式（默认）
按列表优先级选择可用通道，单通道故障自动切下一条；全部失效则直连源站。

### 哈希模式
根据目标 URL 哈希分配固定通道，保证会话连贯；通道故障自动切换其他可用线路。

## 自动探活
后台定时检测通道状态，故障线路自动隔离，恢复后重新加入调度。

## 异常说明

| 情况 | 响应 |
|------|------|
| 路径格式错误 | 400 Bad Request |
| 配置/DSN 解析错误 | 启动失败 |
| 所有通道+源站均不可达 | 502 Bad Gateway |
| 认证失败 | 通道自动标记故障并降级 |

## 依赖
- Rust 1.85+
- tokio (异步运行时)
- hyper (HTTP 服务器/客户端)
- russh (SSH 客户端)

## 开源协议

MIT