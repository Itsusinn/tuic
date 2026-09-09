# TUIC

基于 QUIC 的低延迟代理协议实现，提供独立的服务端与客户端。

本仓库 fork 自 [tuic-protocol/tuic](https://github.com/tuic-protocol/tuic)，在保持 TUIC 简洁、低握手开销特性的同时，增加了更完整的部署、路由、安全与可观测能力。

> 当前版本为 `2.0.0-dev4`，配置格式和功能仍可能调整。升级前请阅读 Release Notes，并备份现有配置。

TUIC 协议的完整定义见[中文规范](crates/wind/specs/tuic.zh_CN.md)或[英文规范](crates/wind/specs/tuic.md)。

## 从源码构建

需要 Rust `1.85.0` 或更高版本、Git，以及目标平台所需的本地构建工具。仓库包含 Git submodule，克隆时请一并初始化：

```console
git clone --recurse-submodules https://github.com/Itsusinn/tuic.git
cd tuic
cargo build --release --package tuic-server --package tuic-client
```

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

## 致谢

感谢原始 [TUIC 项目](https://github.com/tuic-protocol/tuic)、[Wind](https://github.com/rust-proxy/wind) 及所有[贡献者](https://github.com/Itsusinn/tuic/graphs/contributors)。

## 许可证

本仓库代码依据 [GNU General Public License v3.0 or later](LICENSE) 发布。

TUIC 协议概念本身不受该代码许可证限制；你可以独立实现、修改和分发该协议，包括商业用途。
