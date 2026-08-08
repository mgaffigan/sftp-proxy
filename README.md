# SFTP Proxy

SFTP Proxy presents files from an HTTP backend, or from directories on the host,
to standard SFTP and SCP clients. Start with a configuration and an SSH host key,
then point a client at port `2222`.

Create a host key and follow one of the guides below to create `config.json`:

```sh
ssh-keygen -t ed25519 -N '' -f host_key
docker build -t sftp-proxy .
docker run --rm --user 0 -p 2222:2222 \
	-v "$PWD/config.json:/config/config.json:ro" \
	-v "$PWD/host_key:/config/host_key:ro" \
	sftp-proxy
```

Connect with the username from your configuration:

```sh
sftp -P 2222 acme@localhost
```

SCP works over the same filesystem. OpenSSH 9 and later run `scp` over SFTP by
default, which needs nothing extra; `-O` selects the SCP protocol itself, and
both are supported:

```sh
scp -O -P 2222 ./invoice.csv acme@localhost:/Inbound/
scp -O -r -P 2222 acme@localhost:/Outbound ./downloads
```

The example Docker command runs as root only to read the bind-mounted host key.
For a deployed service, supply that key as a secret readable by the image's
default `sftpproxy` user.

## Choose A Workflow

- [Static configuration](docs/static-configuration.md): configure one or more
	users directly and forward a drop-only `Inbound` directory to an upload URL.
- [Local files](docs/local-files.md): serve directories that already exist on
	the host, with no HTTP backend involved.
- [Trivial backend](docs/trivial-backend.md): write a small HTTP backend that
	accepts uploads and offers pending downloads.
- [Advanced backend support](docs/advanced-backend.md): add live directory
	listings, byte ranges, renames, sizes, and directory creation.

## VS Code

The bundled [configuration schema](schemas/sftp-proxy.schema.json) provides
completion and validation. Add this property to a configuration kept at the
repository root:

```json
"$schema": "./schemas/sftp-proxy.schema.json"
```

Adjust the relative path when the configuration lives elsewhere.

## Observability

The proxy emits OpenTelemetry traces for SSH connections, authentication,
SFTP and SCP sessions and operations, and outbound authentication and filesystem
HTTP requests. With no OpenTelemetry exporter configured, completed spans are
written to standard output.

Use the standard OpenTelemetry environment variables to send traces to an
OTLP/HTTP collector:

```sh
OTEL_TRACES_EXPORTER=otlp \
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318 \
docker run --rm --user 0 -p 2222:2222 ... sftp-proxy
```
