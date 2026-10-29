# TUIC 测试分类与入口

以下命令均在 TUIC 仓库根目录运行。按验证范围区分单元测试、集成测试和 E2E；smoke 表示快速检查用途，独立执行且不重复注册到 E2E。

| 分类 | 位置 | 验证边界 |
| --- | --- | --- |
| 单元测试 | `src/unit/`，由 `src/lib.rs` 的 `#[cfg(test)] mod unit` 加载 | 单个逻辑单元的输入输出：协议编解码、重组状态机、配置默认值与反序列化、源码约束。无需真实网络端点。应用自己的单元测试仍留在所属 crate。 |
| 集成测试 | `tests/integration/` | 选定组件之间的协作：outbound 与服务端握手、TLS 记录端点、插件与路由、任务与资源生命周期，以及测试辅助代码和真实套接字/文件系统的配合。可绕过完整客户端入口。 |
| E2E | `tests/e2e/` | 从应用公开网络入口到目标服务，再验证返回结果：SOCKS/forward → 真实 TUIC 客户端 → 服务端 → 目标，或 HTTP/3 请求 → 伪装服务 → 上游。 |
| Smoke | `tests/smoke/` | 四种 Quinn/Quiche 客户端与服务端组合的启动、认证和小数据量 TCP/UDP 回显。是快速的完整链路检查，不承担复杂故障场景。 |
| 共享辅助代码 | `tests/support/`、`src/lib.rs` | 共用连通、转发、代理、回显、TLS 和配置构造逻辑；辅助代码不重复注册测试。 |

`component` 不是单元测试的同义词。此前该目录混合了纯逻辑检查和环境协作检查，现已取消：前者归入库单元测试，后者归入集成测试。Cargo 将 `tests/` 下独立编译的测试程序统称为 integration test targets，这是构建方式；这里的 `integration`、`e2e`、`smoke` 则按验证范围和用途命名。

E2E 使用真实网络和应用 `run` 路径，不代表 CLI 子进程或发布二进制验证。仅启动完整应用但只断言资源释放的测试仍归集成测试；仅有真实 QUIC 握手也不等于完整代理链路。所有网络目标均为本机回环；压力测试、外部服务和性能基准不属于这些入口。

## 执行命令

```console
# 单元测试
cargo test -p tuic-tests --lib --locked --jobs 2

# 快速连通、组件协作、完整应用链路
cargo test -p tuic-tests --test smoke --locked --jobs 2
cargo test -p tuic-tests --test integration --locked --jobs 2
cargo test -p tuic-tests --test e2e --locked --jobs 2

# 按模块或测试名筛选
cargo test -p tuic-tests --test e2e upstream_proxy --locked --jobs 2
cargo test -p tuic-tests --test e2e forwarding --locked --jobs 2
cargo test -p tuic-tests --test e2e relay_semantics --locked --jobs 2
cargo test -p tuic-tests --test integration upstream_proxy --locked --jobs 2
cargo test -p tuic-tests --lib unit::protocol --locked --jobs 2

# 全部默认测试，含文档测试
cargo test -p tuic-tests --locked --jobs 2

# 可选 HTTP/3 伪装 E2E；使用仓库配置提供的 reqwest_unstable
cargo test -p tuic-tests --test e2e --features masquerade-test masquerade --locked --jobs 2

cargo +nightly fmt --all --check
cargo clippy -p tuic-tests --all-targets --locked --jobs 2
```

Quiche 和依赖 `quinn`/`rcgen` 的部分握手测试保留原平台条件：仅受支持的 64 位目标，排除 Android、FreeBSD 和 LoongArch。IPv6 不可用时该用例会记录跳过原因。默认运行不包含 HTTP/3 伪装测试；需要额外启用 `masquerade-test`。

通用 Quinn 链式代理用例不受 Quiche 平台条件限制，以承接旧 SOCKS 测试的平台覆盖。没有测试证书生成依赖的平台沿用本地自签名证书和测试专用验证跳过；SNI/自定义证书检查仍受对应依赖的平台条件限制。

## 覆盖索引

| 入口与模块 | 独立验证的行为 |
| --- | --- |
| E2E `relay_semantics` | 四种后端组合的 TCP 半关闭响应、服务端先发数据及同一 UDP association 的 A→B→A 目标切换 |
| E2E `forwarding` | Quinn/Quiche 客户端，eager/lazy 启动，多规则 TCP/UDP forward、源隔离、UDP idle 后恢复和端口释放 |
| E2E `upstream_proxy` | 认证 SOCKS 链、代理侧 DNS、eager/lazy TCP/UDP、association 与 QUIC 重连，以及经 SOCKS 链的 TCP/UDP forward |
| E2E `concurrency`、`payload_sizes`、`ipv6` | 多流并发、有限载荷边界、IPv6 地址和回环转发 |
| E2E `zero_rtt_config` | 开启 0-RTT 配置后的首次连接仍能完成完整 TCP/UDP 转发 |
| E2E `reconnect_*`、`udp_fragmentation_*` | 完整客户端重连及大于 MTU 的 UDP 分片转发 |
| E2E `restful_traffic_stats`、`masquerade` | 完整代理流量对应的统计、可选 HTTP/3 反向代理请求 |
| 集成 `upstream_proxy` | outbound 释放、代理中断不直连回退、lazy 启动、SNI/ALPN、代理拒绝不直接拨号 |
| 集成 `negative_handshake`、`tls_options` | 两后端的低层握手/鉴权/ACL 失败，以及 Quinn 的 SNI 和自定义 CA 行为 |
| 集成 `quinn_zero_rtt_resumption`、`quiche_zero_rtt_resumption` | 底层 QUIC 会话恢复时实际接受 early data；不经过完整 TUIC 客户端入口 |
| 集成 `quiche_cert_reload` | 入站端点在热重载后握手提供新证书 |
| 集成 `graceful_shutdown`、`guard_drop` | 空闲/有连接/有流量时取消、显式 shutdown 清理及异常 Drop 释放资源 |
| 集成 `echo`、`test_helpers`、`shutdown_config`、`tls_fixture` | 回显辅助函数、目录所有权、证书构造与解析、客户端构建失败 |
| 单元 `protocol`、`codec_boundaries`、`client_defaults` | wire format、codec/decoder 一致性、重组状态机、字段/域名边界和默认配置 |
| 单元 `ipv6_contract`、`port_audit` | 共享超时常量和编译时嵌入源码的约束检查 |

## 迁移与去重规则

- 原 `smoke_relay.rs` 现为 `e2e/relay_semantics.rs`；复杂行为断言不再称作 smoke。
- 原 `integration_tests.rs` 的基础 TCP/UDP 与两个 Quiche 连通文件合并为 smoke 后端矩阵。旧三连接并发段由专用五连接用例覆盖。
- 原 `quinn_zero_rtt.rs`、`quiche_zero_rtt.rs` 合并为 `e2e/zero_rtt_config.rs`，共享连通辅助代码，保留两后端的配置覆盖；真实 early-data 恢复检查留在集成测试。
- 独立 512B 测试由包含 512B 的载荷矩阵覆盖；仅保留矩阵。
- 旧 `proxy_config.rs` 由更完整的代理测试覆盖，其专属源码审计随文件移除。混合代理文件按链路与组件协作拆分到两个入口，仅共享 fixture，不复制测试。
- 旧完整协议 roundtrip 合并进 wire-format/decoder 单元测试，额外校验 codec 解码结果和完整消费；分片字段、数值边界及域名边界保留。
- 同一行为和后端组合只保留一份主要测试。更深层用例中的连通是验证该行为的前置步骤；不同后端、入站方式、TLS 策略和生命周期不因都“能够转发”而视为重复。

新增用例时先确定验证范围，再在 `src/unit/mod.rs` 或对应测试目录的 `main.rs` 注册模块。原 `--test component` 已移除，改用 `--lib` 或 `--test integration`；完整链路改用 `--test e2e`；基础连通统一使用 `--test smoke`。
