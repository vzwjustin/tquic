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

Server:
- `tquic_server --bond` binds all usable local IPs on the listen port when
  `--listen` is a wildcard address and `--listen-addrs` is not provided.
- To pin server addresses, pass `--listen` and `--listen-addrs`.

Client:
- `tquic_client --bond` auto-selects usable local IPs that match the resolved
  server address family when `--local-addresses` is not provided.
- Provide your real server URL as the final argument. To pin client paths, pass
  `--local-addresses` and optionally `--remote-addresses`.

Notes:
- `--remote-addresses` can be omitted to reuse the primary server address for
  all additional paths, or it can provide one address per additional local
  address.
- For custom scheduling, use `--enable-multipath` with
  `--multipath-algor MINRTT|REDUNDANT|ROUNDROBIN` instead of `--bond`.

## License

The project is under the Apache 2.0 license.
