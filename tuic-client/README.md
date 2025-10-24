# tuic-client

Minimalistic TUIC client implementation as a reference

[![Version](https://img.shields.io/crates/v/tuic-client.svg?style=flat)](https://crates.io/crates/tuic-client)
[![License](https://img.shields.io/crates/l/tuic-client.svg?style=flat)](https://github.com/Itsusinn/tuic/blob/dev/LICENSE)

# Overview

The main goal of this TUIC client implementation is not to provide a full-featured, production-ready TUIC client, but to provide a minimal reference for the TUIC protocol client implementation.

This implementation only contains the most basic requirements of a functional TUIC protocol client. If you are looking for features like HTTP-inbound, load-balance, etc., try other implementations, or implement them yourself.

## Usage

Download the latest binary from [releases](https://github.com/Itsusinn/tuic/releases).

Run the TUIC client with configuration file:

```bash
tuic-client -c PATH/TO/CONFIG
```

## Configuration

The client supports both JSON5 and TOML configuration formats:
- **TOML format**: Use `.toml` file extension (recommended for new configurations)
- **JSON5 format**: Use `.json` or `.json5` file extension (legacy format, still supported)

The format is automatically detected based on the file extension. You can also force TOML parsing by setting the `TUIC_FORCE_TOML` environment variable.

```

### TOML Configuration Example

```toml
# TUIC Client Configuration (TOML format)

log_level = "info"

[relay]
# Server address (hostname:port or IP:port)
server = "example.com:443"

# User UUID
uuid = "00000000-0000-0000-0000-000000000000"

# User password
password = "your_password_here"

# Optional: Bind IP address for outgoing connections
# ip = "192.168.1.100"

# IP stack preference: "v4first" (prefer IPv4), "v6first" (prefer IPv6), 
# "v4only" (IPv4 only), "v6only" (IPv6 only)
# Legacy aliases: "v4", "v6", "v4v6", "v6v4", "prefer_v4", "prefer_v6", "only_v4", "only_v6"
ipstack_prefer = "v4first"

# Optional: Custom certificate paths for server verification
# certificates = ["/path/to/cert.pem"]

# UDP relay mode: "native" or "quic"
udp_relay_mode = "native"

# Congestion control algorithm: "cubic", "new_reno", or "bbr"
congestion_control = "cubic"

# ALPN protocols (e.g., ["h3", "h2"])
alpn = []

# Enable 0-RTT handshake
zero_rtt_handshake = false

# Disable SNI (Server Name Indication)
disable_sni = false

# Connection timeout
timeout = "8s"

# Heartbeat interval
heartbeat = "3s"

# Disable native certificate store
disable_native_certs = false

# QUIC send window size (bytes)
send_window = 16777216

# QUIC receive window size (bytes)
receive_window = 8388608

# Initial MTU
initial_mtu = 1200

# Minimum MTU
min_mtu = 1200

# Enable Generic Segmentation Offload (GSO)
gso = true

# Enable Path MTU Discovery
pmtu = true

# Garbage collection interval
gc_interval = "3s"

# Garbage collection lifetime
gc_lifetime = "15s"

# Skip certificate verification (insecure, use only for testing)
skip_cert_verify = false

[local]
# Local SOCKS5 server address
server = "127.0.0.1:1080"

# Optional: SOCKS5 authentication username
# username = "socks_user"

# Optional: SOCKS5 authentication password
# password = "socks_pass"

# Enable dual stack (IPv4 and IPv6)
dual_stack = true

# Maximum UDP packet size
max_packet_size = 1500

# TCP port forwarding rules
# [[local.tcp_forward]]
# listen = "127.0.0.1:8080"
# remote = "example.com:80"

# UDP port forwarding rules
# [[local.udp_forward]]
# listen = "127.0.0.1:5353"
# remote = "8.8.8.8:53"
# timeout = "60s"
```

### JSON5 Configuration Example

```json5
{
    // Settings for the outbound TUIC proxy
    "relay": {
        // Set the TUIC proxy server address
        // Format: "HOST:PORT"
        // The HOST must be a common name in the certificate
        // If the "ip" field in the "relay" section is not set, the HOST is also used for DNS resolving
        "server": "example.com:443",

        // Set the user UUID
        "uuid": "00000000-0000-0000-0000-000000000000",

        // Set the user password
        "password": "PASSWORD",

        // Optional. The IP address of the TUIC proxy server, for overriding DNS resolving
        // If not set, the HOST in the "server" field is used for DNS resolving
        "ip": "127.0.0.1",


        // Optional. Preferred IP stack for connecting to the server.
        // Affects Server dns priority adjustment, therefore this option is invalid when `ip` is set.
        // Can be:
        // - "v4first": Prefer IPv4 addresses, fallback to IPv6
        // - "v6first": Prefer IPv6 addresses, fallback to IPv4
        // - "v4only": Only use IPv4 addresses
        // - "v6only": Only use IPv6 addresses
        // Legacy aliases: "v4", "v6", "v4v6", "v6v4", "prefer_v4", "prefer_v6", "only_v4", "only_v6"
        // Default: "v4first"
        "ipstack_prefer": "v4first",

        // Optional. A list of certificates for TLS handshake
        // System native certificates are also loaded by default
        // When using self-signed certificates, the full certificate chain must be provided
        "certificates": ["PATH/TO/CERTIFICATE_1", "PATH/TO/CERTIFICATE_2"],

        // Optional. Set the UDP packet relay mode
        // Can be:
        // - "native": native UDP characteristics
        // - "quic": lossless UDP relay using QUIC streams, additional overhead is introduced
        // Default: "native"
        "udp_relay_mode": "native",

        // Optional. Congestion control algorithm, available options:
        // "cubic", "new_reno", "bbr"
        // Default: "cubic"
        "congestion_control": "cubic",

        // Optional. Application layer protocol negotiation
        // Default being empty (no ALPN)
        "alpn": ["h3", "spdy/3.1"],

        // Optional. Enable 0-RTT QUIC connection handshake on the client side
        // This is not impacting much on the performance, as the protocol is fully multiplexed
        // WARNING: Disabling this is highly recommended, as it is vulnerable to replay attacks. See https://blog.cloudflare.com/even-faster-connection-establishment-with-quic-0-rtt-resumption/#attack-of-the-clones
        // Default: false
        "zero_rtt_handshake": false,

        // Optional. Disable SNI (Server Name Indication) in TLS handshake
        // The server name used in SNI is the same as the HOST in the "server" field
        // Default: false
        "disable_sni": false,

        // Optional. Set the timeout for establishing a connection to the TUIC proxy server
        // Default: "8s"
        "timeout": "8s",

        // Optional. Set the interval for sending heartbeat packets for keeping the connection alive
        // Default: "3s"
        "heartbeat": "3s",

        // Optional. Disable loading system native certificates
        // Default: false
        "disable_native_certs": false,

        // Optional. Maximum number of bytes to transmit to a peer without acknowledgment
        // Should be set to at least the expected connection latency multiplied by the maximum desired throughput
        // Default: 8MiB * 2
        "send_window": 16777216,

        // Optional. Maximum number of bytes the peer may transmit without acknowledgement on any one stream before becoming blocked
        // Should be set to at least the expected connection latency multiplied by the maximum desired throughput
        // Default: 8MiB
        "receive_window": 8388608,

        // Optional. The initial value to be used as the maximum UDP payload size before running MTU discovery
        // Must be at least 1200
        // Default: 1200
        "initial_mtu": 1200,

        // Optional. The maximum UDP payload size guaranteed to be supported by the network.
        // Must be at least 1200
        // Default: 1200
        "min_mtu": 1200,

        // Optional. Whether to use `Generic Segmentation Offload` to accelerate transmits, when supported by the environment.
        // Default: true
        "gso": true,

        // Optional. Whether to enable Path MTU Discovery to optimize packet size for transmission.
        // Default: true
        "pmtu": true,

        // Optional. Interval between UDP packet fragment garbage collection
        // Default: 3s
        "gc_interval": "3s",

        // Optional. How long the server should keep a UDP packet fragment. Outdated fragments will be dropped
        // Default: 15s
        "gc_lifetime": "15s",

        // Optional. Whether the client should ignore correctness of the server certificate.
        // Default: false
        "skip_cert_verify": false
    },

    // Settings for the local inbound socks5 server
    "local": {
        // Local socks5 server address
        "server": "[::]:1080",

        // Optional. Set the username for socks5 authentication
        "username": "USERNAME",

        // Optional. Set the password for socks5 authentication
        "password": "PASSWORD",

        // Optional. Set if the listening socket should be dual-stack
        // If this option is not set, the socket behavior is platform dependent
        "dual_stack": true,

        // Optional. Maximum packet size the socks5 server can receive from external, in bytes
        // Default: 1500
        "max_packet_size": 1500,
      
        // Optional. TCP/UDP Forwarding allows you to forward one or more TCP/UDP ports
        // from the server (or any remote host) to the client.
        "tcp_forward": [
            {
              // The address to listen on.
              "listen": "127.0.0.1:6600",
              // The address to forward to.
              "remote": "127.0.0.1:6800" 
            }
        ],
        "udp_forward": [
            {
              "listen": "127.0.0.1:16600",
              "remote": "127.0.0.1:16800",
              // Optional. The timeout for each UDP session. 
              // Default: 60 seconds
              "timeout": "60s"
            },
            {
              "listen": "127.0.0.1:44306",
              "remote": "8.8.8.8:443"
            }
        ]
    },

    // Optional. Set the log level
    // Default: "warn"
    "log_level": "warn"
}


## License

GNU General Public License v3.0
