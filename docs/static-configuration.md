# Static Configuration

Use this when one SFTP account drops files into an HTTP endpoint. The proxy
does not authenticate to an HTTP service and does not need an HTTP directory
listing.

Create `config.json` beside the repository's `schemas` directory:

```json
{
  "$schema": "./schemas/sftp-proxy.schema.json",
  "hostKeyFile": "/config/host_key",
  "users": [
    {
      "username": "acme",
      "passwordHash": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
      "rootfs": {
        "children": [
          {
            "directory": "Inbound",
            "backend": "https://files.example.com/inbound",
            "allowedMethods": ["POST"]
          }
        ]
      }
    }
  ]
}
```

By default the proxy listens on all IPv4 and IPv6 interfaces. Set
`bindAddress` to restrict listening to a specific address, such as
`127.0.0.1` for a host-local deployment.

`passwordHash` uses bcrypt. Generate a cost-12 hash by running the proxy in
password-hash mode; it prompts without echoing the password:

```sh
docker run --rm -it sftp-proxy -hash-password
```

Paste the output into `passwordHash`. The example hash is only for the
password `password`. VS Code reads the `$schema` property and offers completion
and validation while the same property is safely ignored by the server.

When a client closes an upload such as `Inbound/invoice.csv`, the proxy makes
one request:

```http
POST https://files.example.com/inbound/invoice.csv
Content-Type: application/octet-stream
```

Return any `2xx` response after storing the body. Files are first staged
privately by the proxy, so an incomplete SFTP upload is never sent.

`allowedMethods` keeps `Inbound` drop-only: the proxy returns an empty client
listing without sending a `GET` to the backend, and only sends `POST` for an
upload. The value accepts `GET`, `POST`, and `DELETE`; omit it for an entry that
supports all of those methods.

Start the server from the repository root:

```sh
ssh-keygen -t ed25519 -N '' -f host_key
docker build -t sftp-proxy .
docker run --rm --user 0 -p 2222:2222 \
  -v "$PWD/config.json:/config/config.json:ro" \
  -v "$PWD/host_key:/config/host_key:ro" \
  sftp-proxy
```

Then connect with `sftp -P 2222 acme@localhost`. The short Docker command runs
as root solely so it can read a host key from a bind mount; a deployed service
can retain the image's default `sftpproxy` user when its key secret is readable
by that user.