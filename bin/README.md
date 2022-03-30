# Running endpoint

## Building

Execute the following commands in Terminal:
```shell
cargo build
```
to build the debug version, or
```shell
cargo build --release
```
to build the release version.

## Issuing self-signed cert and keys (RSA)

Execute the following commands in Terminal:
```shell
openssl req -config <openssl.conf> -new -x509 -sha256 -newkey rsa:2048 -nodes -days 1000 -keyout key.pem -out cert.pem
```
where
* `<openssl.conf>` is an OpenSSL request template file

## Endpoint configuration

An endpoint can be configured using a JSON file. The file struct reflects the library settings
(see `struct Settings` in [settings.rs](../src/settings.rs)).
The very basic configuration file can be found in [the example](#example-endpoint).
To explore the full set of settings see docs in [settings.rs](../src/settings.rs).

## Running

To run the binary through `cargo`, execute the following commands in Terminal:
```shell
cargo run --bin vpn_endpoint -- <path/to/vpn.config>
```

To run the binary directly, execute the following commands in Terminal:
```shell
<path/to/target>/vpn_endpoint <path/to/vpn.config>
```
where `<path/to/target>` is determined by the build command (by default it is `./target/debug` or
`./target/release` depending on the build type).

## Example endpoint

For a quic setup you can run the example endpoint (see [here](../examples/my_vpn)).
It shows the essential things needed to run an instance.
To start one run the following commands in Terminal:
```shell
cd ../examples/my_vpn && ./run.sh
```
It may ask you to enter some information for generating your certificate.
Skip it clicking `enter` if it does not matter.
