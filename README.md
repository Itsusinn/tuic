# TUIC

基于 QUIC 的低延迟代理协议实现，提供独立的服务端与客户端。

本仓库 fork 自 [tuic-protocol/tuic](https://github.com/tuic-protocol/tuic)，在保持 TUIC 简洁、低握手开销特性的同时，增加了更完整的部署、路由、安全与可观测能力。

> 当前版本为 `2.0.0-dev1`，配置格式和功能仍可能调整。升级前请阅读 Release Notes，并备份现有配置。

## 特性

- TCP 与 UDP 代理，支持完全多路复用
- 0-RTT 连接、认证及 TCP/UDP 转发
- `native` 与 `quic` 两种 UDP 中继模式
- 本地 SOCKS5 代理、TCP/UDP 端口转发及断线自动重连
- BBR、BBRv3、CUBIC、New Reno 等拥塞控制算法
- ACL 与 Metacubex 风格路由规则
- 直连和 SOCKS5 出站，可指定 IP 栈、源地址或网络接口
- 自动 ACME 证书、自签名证书与证书热重载
- HTTP/3 伪装、GeoIP/GeoSite 规则与流量统计 API
- Quinn 后端，以及实验性的 tokio-quiche 后端
- Linux、Windows、macOS、FreeBSD 等平台构建
- `linux/amd64`、`linux/arm64` 多架构容器镜像

TUIC 协议的完整定义见[中文规范](crates/wind/specs/tuic.zh_CN.md)或[英文规范](crates/wind/specs/tuic.md)。

## 快速开始

### 1. 获取程序

可从项目的 [Releases](https://github.com/Itsusinn/tuic/releases) 下载适合当前平台的 `tuic-server` 和 `tuic-client`，也可以按照后文说明从源码构建。

### 2. 创建服务端配置

生成 UUID，并为它设置一个高强度密码。下面的配置使用自签名证书，适合首次测试：

```toml
# server.toml
server = "[::]:8443"
log_level = "info"

[users]
"00000000-0000-0000-0000-000000000000" = "请替换为高强度密码"

[tls]
self_sign = true
hostname = "你的服务器域名"
```

启动服务端：

```console
tuic-server -c server.toml
```

服务端还可以生成一份包含全部选项的示例配置：

```console
tuic-server --init
```

该命令会在当前目录创建 `config.toml`，若文件已经存在则不会覆盖。

### 3. 创建客户端配置

```toml
# client.toml
log_level = "info"

[relay]
server = "你的服务器域名:8443"
uuid = "00000000-0000-0000-0000-000000000000"
password = "请替换为高强度密码"
udp_relay_mode = "native"
congestion_control = "bbr"

# 仅在服务端使用自签名证书进行测试时启用。
# 生产环境请改用受信任证书，或通过 certificates 指定证书文件。
skip_cert_verify = true

[local]
server = "127.0.0.1:1080"
```

启动客户端：

```console
tuic-client -c client.toml
```

随后将应用的 SOCKS5 代理设置为 `127.0.0.1:1080`。服务端监听的是 UDP 端口，请确认防火墙和云安全组已放行 `8443/udp`。

## 生产环境 TLS

建议使用受信任的证书，并关闭客户端的 `skip_cert_verify`。

使用已有证书：

```toml
[tls]
certificate = "/etc/tuic/fullchain.pem"
private_key = "/etc/tuic/privatekey.pem"
hostname = "tuic.example.com"
```

或通过 ACME 自动申请证书：

```toml
[tls]
auto_ssl = true
hostname = "tuic.example.com"
acme_email = "admin@example.com"
```

域名应正确解析到服务器，申请证书所需的端口和网络访问也必须可用。请妥善保护私钥、用户密码及管理 API 密钥。

## Docker

服务端镜像发布于 GitHub Container Registry：

```console
docker pull ghcr.io/itsusinn/tuic-server:latest

docker run -d \
  --name tuic-server \
  --restart unless-stopped \
  -p 8443:8443/udp \
  -v "$PWD/server.toml:/etc/tuic/config.toml:ro" \
  ghcr.io/itsusinn/tuic-server:latest
```

容器默认从 `/etc/tuic` 中查找配置文件。若需持久化自动签发的证书或其他运行数据，请在配置中设置 `data_dir`，并将对应目录挂载到宿主机。

Docker Compose 与 Podman Quadlet 的完整部署说明见 [CONTAINER.md](CONTAINER.md)。

## 配置

客户端和服务端均支持 TOML、YAML、JSON 与 JSON5，并通常根据文件扩展名识别格式。

常用命令：

```console
tuic-server --help
tuic-client --help

tuic-server -c /path/to/config.toml
tuic-server -d /path/to/config-directory
tuic-client -c /path/to/config.toml
```

如扩展名无法表达实际格式，可以设置 `TUIC_CONFIG_FORMAT`，可选值为 `toml`、`yaml`、`json` 或 `json5`。兼容旧部署的 `TUIC_FORCE_TOML` 也受支持，并具有更高优先级。

更多可用配置可以参考：

- [客户端完整 TOML 示例](crates/tuic-client/tests/config/toml_full_config.toml)
- [服务端基础 TOML 示例](crates/tuic-server/tests/config/valid_toml_config.toml)
- [服务端出站配置示例](crates/tuic-server/tests/config/outbound_valid_with_default.toml)
- [ACL IR 规范](crates/wind/specs/acl-ir.zh_CN.md)

## 从源码构建

需要 Rust `1.85.0` 或更高版本、Git，以及目标平台所需的本地构建工具。仓库包含 Git submodule，克隆时请一并初始化：

```console
git clone --recurse-submodules https://github.com/Itsusinn/tuic.git
cd tuic
cargo build --release --package tuic-server --package tuic-client
```

如果仓库已经克隆：

```console
git submodule update --init --recursive
```

生成的程序位于 `target/release/`。默认使用 AWS-LC-RS；如需使用 ring：

```console
cargo build --release --no-default-features --features ring --package tuic-server
cargo build --release --no-default-features --features ring --package tuic-client
```

实验性的 quiche 服务端后端需要显式启用 `quiche` feature，且目前仅支持 64 位目标。

## 测试与开发

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets
cargo test --workspace
```

工作区包含以下主要 crate：

- `tuic-server`：服务端程序、TLS、路由、出站与管理 API
- `tuic-client`：客户端程序、本地 SOCKS5 与端口转发
- `tuic-tests`：协议与端到端集成测试
- `wind`：通过 Git submodule 引入的网络代理框架与 TUIC 协议实现

欢迎提交 Issue 和 Pull Request。请从 `main` 分支派生改动并向 `main` 提交；`next` 等开发分支可能发生历史重写。使用 AI 辅助的贡献还须遵循 [LLM.md](LLM.md) 中的披露要求。

## 安全提示

- 不要在公开仓库、日志或截图中泄露 UUID、密码、私钥和 API 密钥。
- `skip_cert_verify = true` 会跳过服务端身份校验，只应临时用于受控测试。
- 默认的回环与私有地址保护有助于降低 SSRF 风险；仅在明确了解影响时关闭。
- 若管理 API 暴露到非本机地址，请设置 Bearer Token，并在外层增加访问控制。
- 0-RTT 数据可能被重放；不要通过早期数据执行不可重复的敏感操作。

如发现安全问题，请避免直接公开利用细节，优先通过仓库维护者提供的私密渠道报告。

## 致谢

感谢原始 [TUIC 项目](https://github.com/tuic-protocol/tuic)、[Wind](https://github.com/rust-proxy/wind) 及所有[贡献者](https://github.com/Itsusinn/tuic/graphs/contributors)。

## 许可证

本仓库代码依据 [GNU General Public License v3.0 or later](LICENSE) 发布。

TUIC 协议概念本身不受该代码许可证限制；你可以独立实现、修改和分发该协议，包括商业用途。
