<!-- markdownlint-disable MD041 -->
<p align="center">
<picture>
<source media="(prefers-color-scheme: dark)" srcset="https://cdn.adguardcdn.com/website/github.com/TrustTunnel/logo_dark.svg" width="300px" alt="TrustTunnel" />
<img src="https://cdn.adguardcdn.com/website/github.com/TrustTunnel/logo_light.svg" width="300px" alt="TrustTunnel" />
</picture>
</p>

<p align="center"><a href="https://github.com/TrustTunnel/TrustTunnelClient">Console client</a>
  · <a href="https://github.com/TrustTunnel/TrustTunnelFlutterClient">Flutter-based app</a>
  · <a href="https://agrd.io/ios_trusttunnel">App store</a>
  · <a href="https://agrd.io/android_trusttunnel">Play store</a>
</p>

---

## Table of Contents

- [Introduction](#introduction)
- [Server Features](#server-features)
- [Client Features](#client-features)
- [Quick start](#quick-start)
    - [Endpoint setup](#endpoint-setup)
        - [Install the endpoint](#install-the-endpoint)
        - [TrustTunnel Flutter Client 1.0 Warning](#trusttunnel-flutter-client-10-warning)
        - [Endpoint configuration wizard](#endpoint-configuration-wizard)
        - [Running endpoint](#running-endpoint)
        - [Export client configuration](#export-client-configuration)
    - [Client setup](#client-setup)
        - [Install the client](#install-the-client)
        - [Client configuration wizard](#client-configuration-wizard)
        - [Running client](#running-client)
- [See also](#see-also)
- [Roadmap](#roadmap)
- [License](#license)

---

## Introduction

TrustTunnel is a modern, open-source VPN protocol originally developed by
[AdGuard VPN][adguard-vpn] and now available for anyone to use, audit, and use.

It delivers fast, secure, and reliable VPN connections without the usual trade-offs.
By design, TrustTunnel traffic is indistinguishable from regular HTTPS traffic,
allowing it to bypass throttling and deep-packet inspection while maintaining
strong privacy protections.

The TrustTunnel project includes the VPN endpoint (this repository), the
[library and CLI for the client][trusttunnel-client],
and the [GUI application][trusttunnel-flutter-client].

[adguard-vpn]: https://adguard-vpn.com
[trusttunnel-client]: https://github.com/TrustTunnel/TrustTunnelClient
[trusttunnel-flutter-client]: https://github.com/TrustTunnel/TrustTunnelFlutterClient

## Server Features

- **VPN Protocol**: The library implements the VPN protocol compatible
  with HTTP/1.1, HTTP/2, and QUIC. By mimicking regular network traffic, it
  becomes impossible to detect and block.

- **Flexible Traffic Tunneling**: TrustTunnel can tunnel TCP, UDP, and ICMP
  traffic to and from the client.

- **Platform Compatibility**: The server is compatible with Linux and macOS.
  The client is available for Android, Apple, Windows, and Linux.

---

## Client Features

- **Traffic Tunneling**: The library is capable of tunneling TCP, UDP, and ICMP
  traffic from the client to the endpoint and back.

- **Cross-Platform Support**: It supports Linux, macOS, and Windows platforms,
  providing a consistent experience across different operating systems.

- **System-Wide Tunnel and SOCKS5 Proxy**: It can be set up as a system-wide
  tunnel, utilizing a virtual network interface, as well as a SOCKS5 proxy.

- **Split Tunneling**: The library supports split tunneling, allowing users to
  exclude connections to certain domains or hosts from routing through the VPN
  endpoint, or vice versa, only routing connections to specific domains or hosts
  through the endpoint based on an exclusion list.

- **Custom DNS Upstream**: Users can specify a custom DNS upstream, which is
  used for DNS queries routed through the VPN endpoint.

---

## Quick start

### Endpoint setup

#### Install the endpoint

An installation script is available that can be run with the following command:

```bash
curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh | sh -s -
```

The installation script will download the prebuilt package from the latest
GitHub release for the appropriate system architecture and unpack it to
`/opt/trusttunnel`. The output directory could be overridden by specifying
`-o DIR` flag at the end of the command above.

> [!NOTE]
> Currently only `linux-x86_64` and `linux-aarch64` architectures are provided
> for the prebuilt packages.

#### TrustTunnel Flutter Client 1.0 Warning

> [!WARNING]
> TrustTunnel Flutter Client **doesn't support** self-signed certificates **yet**.
> If you want to use the TrustTunnel Flutter Client, you should have a valid
> certificate issued by a publicly trusted Certificate Authority (CA) associated
> with a registered domain for the IP address of the endpoint. Otherwise,
> the TrustTunnel Flutter Client will be unable to connect to the endpoint.

#### Endpoint configuration wizard

Please refer to the [CONFIGURATION.md](CONFIGURATION.md) for the more detailed
documentation on how to configure the endpoint.

The installation directory contains `setup_wizard` binary that helps generate
the config files required for the endpoint to run:

```bash
cd /opt/trusttunnel/
./setup_wizard -h
```

The setup wizard supports interactive mode, so you could run it and it will ask
for data required for endpoint configuration.

```bash
cd /opt/trusttunnel/
./setup_wizard
```

The wizard will ask for the following fields, some of them have the default
values you could safely use:

- **The address to listen on** - specify the address for the endpoint to listen
  on. Use the default `0.0.0.0:443` if you want the endpoint to listen on port
  443 (HTTPS) on all interfaces.
- **Path to credentials file** - path where the user credentials for
  authorization will be stored.
- **Username** - the username the user will use for authorization.
- **Password** - the user's password.
- **Add one more user?** - select `yes` if you want to add more users, or `no`
  to continue the configuration process.
- **Path to the rules file** - path to store the filtering rules.
- **Connection filtering rules** - you can add rules that the endpoint will use
  to allow or disallow user's connections based on:
    - Client IP address
    - TLS random prefix
    - TLS random with mask

  Press `n` to allow all connections.
- **Path to a file to store the library settings** - path to store the main
  endpoint configuration file.
- **Certificate selection** - choose how to obtain a TLS certificate:
    - **Issue a Let's Encrypt certificate** (requires a public domain) - the
      setup wizard has built-in ACME support and can automatically obtain a free,
      publicly trusted certificate from Let's Encrypt. You'll need:
        - A registered domain pointing to your server's IP address
        - Port 80 accessible from the internet (for HTTP-01 challenge), or
        - Ability to add DNS TXT records (for DNS-01 challenge)
    - **Generate a self-signed certificate** - suitable for testing or when using
      the CLI client only. Note: The Flutter client does not support self-signed
      certificates **yet**.
    - **Provide path to existing certificate** - use your own certificate files
      obtained from another CA or tool like [certbot][certbot].
- **Path to a file to store the TLS hosts settings** - path to store the TLS host settings file.

At this point all required configuration files are created and saved on disk.

[certbot]: https://eff-certbot.readthedocs.io/en/stable/

#### Running endpoint

The installed package contains the systemd service template, named
`trusttunnel.service.template`.

This template can be used to set up the endpoint as a systemd service:

> [!NOTE]
> The template file assumes that the TrustTunnel Endpoint binary and all its
> configuration files are located in `/opt/trusttunnel` and have the default
> file names. Modify the template if you have used the different paths.

```bash
cd /opt/trusttunnel/
cp trusttunnel.service.template /etc/systemd/system/trusttunnel.service
sudo systemctl daemon-reload
sudo systemctl enable --now trusttunnel
```

#### Export client configuration

The endpoint binary is capable of generating the client configuration for
a particular user.

This configuration contains all necessary information that is required to
connect to the endpoint.

To generate the configuration, run the following command:

```shell
# <client_name> - name of the client those credentials will be included in the configuration
# <public_ip_and_port> - `ip:port` that the user will use to connect to the endpoint
cd /opt/trusttunnel/
./trusttunnel_endpoint vpn.toml hosts.toml -c <client_name> -a <public_ip_and_port>
```

This will print the configuration with the credentials for the client named
`<client_name>`.

The generated client configuration could be used to set up the
[TrustTunnel Flutter Client][trusttunnel-flutter-client], refer to the
documentation in [its repository][trusttunnel-flutter-configuration].

Congratulations! You've done setting up the endpoint!

[trusttunnel-flutter-configuration]: https://github.com/TrustTunnel/TrustTunnelFlutterClient/blob/master/README.md#server-configuration

### Client setup

#### Install the client

You have a choice to use a [CLI client][trusttunnel-client] or a
[GUI client][trusttunnel-flutter-client].

To install the CLI client, run the following command:

```bash
curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnelClient/refs/heads/master/scripts/install.sh | sh -s -
```

The installation script will download the prebuilt package from the latest GitHub release for the appropriate system architecture and unpack it to `/opt/trusttunnel_client`. The output directory could be overridden by specifying `-o DIR` flag at the end of the command above.

> [!NOTE]
> Install script supports x86_64, aarch64, armv7, mips and mipsel architectures
> for linux and arm64 and x86_64 for macos.

#### Client configuration wizard

The installation directory contains `setup_wizard` binary that helps generate
the config files required for the client to run:

```bash
cd /opt/trusttunnel_client/
./setup_wizard -h
```

To configure the client to use the config that was generated by endpoint, run
the following command:

```bash
./setup_wizard --mode non-interactive \
     --endpoint_config <endpoint_config> \
     --settings trusttunnel_client.toml
```

where `<endpoint_config>` is path to a config generated by the endpoint.

`trusttunnel_client.toml` will contain all required configuration for the
client.

#### Running client

To run the client execute the following command:

```bash
cd /opt/trusttunnel_client/
sudo ./trusttunnel_client -c trusttunnel_client.toml
```

`sudo` is required to set up the routes and tun interface.

## See Also

- [CONFIGURATION.md](CONFIGURATION.md) - Configuration documentation
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development documentation
- [CHANGELOG.md](CHANGELOG.md) - Changelog

## Roadmap

While our VPN currently supports tunneling TCP/UDP/ICMP traffic, we plan to add support for
peer-to-peer communication between clients.

Stay tuned for this feature in upcoming releases.

## License

This project is licensed under the Apache 2.0 License. See [LICENSE.md](LICENSE.md) for details.
