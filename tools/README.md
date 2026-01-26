# TQUIC tools

[TQUIC](https://github.com/Tencent/tquic) is a high-performance, lightweight, and cross-platform library for the [IETF QUIC](https://datatracker.ietf.org/wg/quic/bout/) protocol. 

The crate contains client and server tools based on TQUIC:
- tquic_client: A QUIC and HTTP/3 client. It's also an HTTP/3 benchmarking tool.
- tquic_server: A QUIC and HTTP/3 static file server.


## Installation

```
cargo install tquic_tools
```


## Documentation

- [English version](https://tquic.net/docs/getting_started/demo/)
- [Chinese version](https://tquic.net/zh/docs/getting_started/demo/)


## Multipath bonding setup

To bond multiple WANs with redundant scheduling, run both server and client
with `--bond`. This enables multipath and forces the redundant scheduler.

Server (bind each WAN address):

```
tquic_server --bond --listen <SERVER_WAN1:PORT> --listen-addrs <SERVER_WAN2:PORT>,<SERVER_WAN3:PORT>
```

Client (bind each local WAN and optionally map to server WANs):

```
tquic_client --bond --local-addresses <CLIENT_WAN1_IP>,<CLIENT_WAN2_IP> \
  --remote-addresses <SERVER_WAN2:PORT> <URL>
```

Notes:
- `--remote-addresses` can be omitted to reuse the primary server address for
  all additional paths, or it can provide one address per additional local
  address.
- For custom scheduling, use `--enable-multipath` with
  `--multipath-algor MINRTT|REDUNDANT|ROUNDROBIN` instead of `--bond`.

## License

The project is under the Apache 2.0 license.
