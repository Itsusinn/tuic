# ECH 配置

Quiche 服务端支持 Quinn 和 Quiche 客户端通过 ECH 连接。Quinn 客户端需要默认启用的 `aws-lc-rs` feature 提供 HPKE；仅 `ring` 构建配置 ECH 会明确报错。Quinn 服务端依赖的 Rustls 尚无服务端 ECH 实现，设置服务端 `tls.ech` 会报错。

ECH 默认关闭。服务端需要独立的二进制 `ECHConfig` 和原始 32 字节 X25519 私钥，客户端需要对应的二进制 `ECHConfigList`。这些文件不是 PEM，也不是 Base64 文本；ECH 私钥与证书私钥不同。可使用 BoringSSL 的工具生成：

```console
bssl generate-ech -public-name public.example -config-id 1 -out-ech-config ech.config -out-ech-config-list ech.list -out-private-key ech.key
```

服务端保留原有证书配置，并添加：

```toml
[backend]
mode = "quiche"

[tls.ech]
config = "ech.config"
private_key = "ech.key"
```

通过配置文件启动服务端时，上述相对路径以 `data_dir` 为基准。保护 ECH 私钥，只将 `ech.list` 分发给客户端。服务端当前加载一个 ECH 密钥，修改后需要重启；证书热更新不会移除 ECH 密钥。

客户端添加（`mode` 可选 `quinn` 或 `quiche`）：

```toml
[backend]
mode = "quinn"

[tls]
sni = "private.example"
ech_config_list = "ech.list"
```

客户端文件路径以进程工作目录为基准。`sni` 是内部服务名，服务器证书仍需对该名称有效且受客户端信任。外层公开名称来自 ECH 配置。ECH 不替代证书验证，默认仍验证证书；不能同时设置 `disable_sni = true`。Quinn 客户端仍支持用 `tls.certificates` 添加自定义信任证书。

客户端设置 `ech_config_list` 后必须成功协商 ECH，才允许发送 TUIC 鉴权和代理流量。配置无效、没有可用版本、密钥过期、服务器拒绝或不支持 ECH 时均失败；不自动重试服务器提供的新配置，也不降级为无 ECH。已有重连逻辑会继续使用所配置的 ECHConfigList。

本功能不查询 DNS HTTPS 记录，配置分发由部署者管理。没有设置 ECH 的客户端仍可连接启用了 ECH 的服务端。

验证入口：

```console
cargo test -p tuic-tests --test e2e ech:: --jobs 2
cargo test -p tuic-tests --test integration ech:: --jobs 2
```

E2E 覆盖 Quinn/Quiche 两种客户端的完整 SOCKS5 → TUIC 客户端 → Quiche 服务端 → TCP/UDP 回显，以及踢线后重连和启用会话恢复时的兼容性。Quinn 用例信任临时生成的证书并验证内部主机名，Quiche 用例使用临时自签名证书并显式跳过证书验证。启用会话恢复的用例不宣称实际接受了 0-RTT。集成测试覆盖两种客户端的 ECH 拒绝和配置错误，以及 Quinn 客户端对不可信证书和错误内部主机名的拒绝。
