# tuic-server

Minimalistic TUIC server implementation as a reference

[![Version](https://img.shields.io/crates/v/tuic-server.svg?style=flat)](https://crates.io/crates/tuic-server)
[![License](https://img.shields.io/crates/l/tuic-server.svg?style=flat)](https://github.com/EAimTY/tuic/blob/dev/LICENSE)

# Overview

The main goal of this TUIC server implementation is not to provide a full-featured, production-ready TUIC server, but to provide a minimal reference for the TUIC protocol server implementation.

This implementation only contains the most basic requirements of a functional TUIC protocol server. If you are looking for features like outbound-control, DNS-caching, etc., try other implementations, or implement them yourself.

## Usage

Download the latest binary from [releases](https://github.com/Itsusinn/tuic/releases).

Or install from [crates.io](https://crates.io/crates/tuic-server):

```bash
cargo install --git https://github.com/Itsusinn/tuic.git tuic-server
```

Run the TUIC server with configuration file:

```bash
tuic-server -c PATH/TO/CONFIG
```

Or with Docker

```bash
docker run --name tuic-server \
  --restart always \
  --network host \
  -v /PATH/TO/CONFIG:/etc/tuic/config.json \
  -v /PATH/TO/CERTIFICATE:PATH/TO/CERTIFICATE \
  -v /PATH/TO/PRIVATE_KEY:PATH/TO/PRIVATE_KEY \
  -dit ghcr.io/itsusinn/tuic-server:latest
```

Or with Docker Compose

```yaml
services:
  tuic:
    image: ghcr.io/itsusinn/tuic-server:latest
    restart: always
    container_name: tuic
    network_mode: host
    volumes:
      - ./config.json:/etc/tuic/config.json:ro
      - ./cert.crt:/PATH/TO/CERT:ro
      - ./key.crt:/PATH/TO/KEY:ro
```

If you use TOML format configuration


```yaml
services:
  tuic:
    image: ghcr.io/itsusinn/tuic-server:latest
    restart: always
    container_name: tuic
    network_mode: host
    volumes:
      - ./config.toml:/etc/tuic/config.json:ro # Must be /path/to/toml:/etc/tuic/*config.json*:ro, this will be fix in 2.0.0.
      - ./cert.crt:/PATH/TO/CERT:ro
      - ./key.crt:/PATH/TO/KEY:ro
    environment:
      - TUIC_FORCE_TOML=1
```

## Configuration

Since `tuic-server 1.2.0`, the new TOML format has been used. The old JSON format will be kept until `2.0.0`.

`tuic-server -c server.toml`

```toml
# server.toml
### You can generate example configuration by using `tuic-server -i` or `tuic-server --init`
### ALL settings are OPTIONAL, if you leave one empty, default value will be used

log_level = "info" # Default: info

# The socket address to listen on
server = "[::]:443" # Default: "[::]:443"

# Whether the server should create separate UDP sockets for relaying IPv6 UDP packets
udp_relay_ipv6 = true # Default: true

# Enable 0-RTT QUIC connection handshake on the server side
# This is not impacting much on the performance, as the protocol is fully multiplexed
# WARNING: Disabling this is highly recommended, as it is vulnerable to replay attacks. See https://blog.cloudflare.com/even-faster-connection-establishment-with-quic-0-rtt-resumption/#attack-of-the-clones
zero_rtt_handshake = false # Default: false

# Set if the listening socket should be dual-stack
# If this option is not set, the socket behavior is platform dependent
dual_stack = true # Default: true

# How long the server should wait for the client to send the authentication command
auth_timeout = "3s" # Default: "3s"

# Maximum duration server expects for task negotiation
task_negotiation_timeout = "3s" # Default: "3s"

# Interval between UDP packet fragment garbage collection
gc_interval = "3s" # Default: "3s"

# How long the server should keep a UDP packet fragment. Outdated fragments will be dropped
gc_lifetime = "15s" # Default: "15s"

# Maximum packet size the server can receive from outbound UDP sockets, in bytes
max_external_packet_size = 1500

# How long should server perserve TCP and UDP I/O tasks.
stream_timeout = "10s" # Default: "10s"

# Working Directory of tuic
data_dir = "" # Default: `CWD`

# User list, contains user UUID and password
[users] # Default: empty
f0e12827-fe60-458c-8269-a05ccb0ff8da = "YOUR_USER_PASSWD_HERE"

[tls]
# Whether use auto-generated self-signed certificate and key.
# When enabled, the follwing `certificate` and `private_key` fields will be ignored.
self_sign = true # Default: false

# The path to the certificate file
# Relative path of `data_dir`, if it's relative
certificate = "/PATH/TO/CERT" # Default: ""

# The path to the private key file
# Relative path of `data_dir`, if it's relative
private_key = "/PATH/TO/KEY" # Default: ""

# Application layer protocol negotiation
alpn = ["h3"] # Default: empty

# Enable automatic SSL certificate provision
# If enabled, will ignore `self_sign`, if failed, will fallback to self-sign
# If both certificate and private_key are set, will be the path to save certificate and key
# Note ACME HTTP-01 challenge requires listen on :80,
# to allow non-root processes to bind to privileged ports on Linux, run:
# setcap CAP_NET_BIND_SERVICE=+eip <path to tuic-server binary>
auto_ssl = true # Default: false
# Hostname used for automatic SSL certificate provision / self-sign
hostname = "example.org" # Default: "localhost"

# See `RESTful API` section below in README.
# If you want disable RESTful function, remove entire `restful` section.
[restful] # Default: empty
addr = "127.0.0.1:8443" # Default: "127.0.0.1:8443"
# Set secret to "" to disable authorization
secret = "YOUR_SECRET_HERE" # Default: "YOUR_SECRET_HERE"

# Limit how many clients one uuid can have at the same time.
# Clients under same IP are considered as DIFFERENT clients
maximum_clients_per_user = 0

[quic]
# The initial value to be used as the maximum UDP payload size before running MTU discovery
# Must be at least 1200
initial_mtu = 1200

# The maximum UDP payload size guaranteed to be supported by the network.
# Must be at least 1200
min_mtu = 1200 # Default: 1200

# Whether to use `Generic Segmentation Offload` to accelerate transmits, when supported by the environment.
gso = true # Default: true

# Whether to enable Path MTU Discovery to optimize packet size for transmission.
pmtu = true # Default: true

# Maximum number of bytes to transmit to a peer without acknowledgment
# Should be set to at least the expected connection latency multiplied by the maximum desired throughput
send_window = 16777216 # Default: 8MiB * 2

# Maximum number of bytes the peer may transmit without acknowledgement on any one stream before becoming blocked
# Should be set to at least the expected connection latency multiplied by the maximum desired throughput
receive_window = 8388608 # Default: 8MiB

# How long the server should wait before closing an idle connection
max_idle_time = "10s"


[quic.congestion_control]
# Congestion control algorithm, available options: "cubic", "new_reno", "bbr"
controller = "bbr" # Default: "bbr"

# Sets the initial congestion window size in bytes for the congestion controller algorithm, which may improve burst performance but could lead to congestion under high concurrency.
initial_window = 1048576 # Default: 1048576

[outbound]
# If no default outbound rule is configured then the following default rule will be used
# The name of the outbound will be used in ACL rules, 
# TODO: currently ONLY the 'default' outbound rule is used, others are ignored. 
[outbound.default]
type = "direct"
ip_mode = "auto"
[outbound.prefer_v4]
# "direct" / "socks5"
type = "direct"
# Optional, default to "auto", the dual-stack "happy eyeballs" mode. The client will attempt to connect to 
# the destination using both IPv4 and IPv6 addresses (if available), and use the first one that succeeds.
# Available options: `prefer_v4`, `prefer_v6`, `only_v4`, `only_v6`, `auto`
ip_mode = "prefer_v4"
# Optional, the local IPv4 address to bind to when the proxy target is IPv4
bind_ipv4 = "1.2.3.4"
# Optional, the local IPv6 address to bind to when the proxy target is IPv6
bind_ipv6 = "0:0:0:0:0:ffff:0102:0304"
# Optional, The local network interface to bind to. Sets the value for the `SO_BINDTODEVICE` option on outbound sockets.
# If a socket is bound to an interface, only packets received from that particular interface are processed by the
# socket. Note that this only works for some socket types, particularly AF_INET sockets.
bind_device = "eth1234"
[outbound.v6_only]
type = "direct"
ip_mode = "only_v6"
[outbound.through_socks5]
# TODO: `socks5` outbound is not implemented yet
type = "socks5"
# SOCKS5 proxy addr
addr = "127.0.0.1:1080"
# Optional
username = "optional"
# Optional
password = "optional" 

```
## Notes

TLS cert and key is NECESSARY, to automatically get them, recommend use [acme.sh](https://github.com/acmesh-official/acme.sh)

```sh
acme.sh --issue -d www.yourdomain.org --standalone
acme.sh --install-cert -d www.yourdomain.org \
--key-file       /CERT_PATH/key.crt  \
--fullchain-file /CERT_PATH/cert.crt
```

## RESTful API
With authorization header when making a request. `curl -H 'Authorization: Bearer YOUR_SECRET_HERE' http://ip:port/path`

Or with authorization disabled `curl  http://ip:port/path`

APIs:
- GET `http://ip:port/online`
  > List online clients' count.
  Response: TODO

- GET `http://ip:port/detailed_online`
  > List online clients' IP address and port.
  Response: TODO

- POST `http://ip:port/kick`

  Request: ["userA", "userB"]
  > Clients can always reconnect after being kicked.

  Response: TODO

- GET `http://ip:port/traffic`

  Return current traffic stats.
  > Traffic data will be lost when `tuic-server` restarts.

  Response: TODO

- GET `http://ip:port/reset_traffic`

  Reset traffic stats and return previous traffic stats.
  > Traffic data will be lost when `tuic-server` restarts.

  Response: TODO

## License

GNU General Public License v3.0
