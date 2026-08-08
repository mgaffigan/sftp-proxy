# Authentication Backend

Configure one authentication backend mode. Static users take precedence over
either backend.

## Username+Password Only

`authBackend.url` is a single-round-trip password-only endpoint:

```json
{
  "authBackend": {
    "url": "https://auth.example.test/sftp/auth"
  }
}
```

The proxy sends a JSON `POST`:

```json
{
  "connection": {
    "username": "acme",
    "remoteAddress": "203.0.113.10:54321",
    "localAddress": "192.0.2.20:2222",
    "clientVersion": "SSH-2.0-OpenSSH_...",
    "serverVersion": "SSH-2.0-Go"
  },
  "password": "secret",
  "method": "password"
}
```

Return `2xx` with the session user in the shape of the static user's `user` object:

```json
{
  "user": {
    "rootfs": {
      "children": [
        ...
      ]
    }
  }
}
```

`user.username` defaults to the requested username and must match it when
present. Any non-`2xx` response rejects authentication. Public-key 
authentication is unavailable in the single-endpoint mode.

Cookies returned by the backend are retained for the SSH connection and used for 
httpfs filesystem requests.

See [trivial backend](trivial-backend.md) for an example of a simple HTTP 
backend that only supports password authentication.

## Public Key, or Password + Public Key

`authBackend.baseURL` supports password and public-key authentication, at the
SSH imposed cost of an additional round-trip for public-key discovery.

Configure the base URL of the public-key capable authentication backend:

```json
{
  "authBackend": {
    "baseURL": "https://auth.example.test"
  }
}
```

The proxy posts the same `connection` object to these paths below `baseURL`:

| Path | Request | Successful response |
| --- | --- | --- |
| `/v1/sftp/auth/lookup` | `{"connection": {...}}` | `{"methods":["password","publickey"],"authorizedKeys":["ssh-ed25519 AAAA..."]}` |
| `/v1/sftp/auth/password` | `{"connection": {...},"password":"secret"}` | Any `2xx`. |
| `/v1/sftp/auth/finalize` | `{"connection": {...},"method":"password"}` | `{"user":{"rootfs":{"children":[]}}}` |

For public-key authentication, the proxy verifies the presented key against
`authorizedKeys` and calls `finalize` instead of `password`:

```json
{
  "connection": { "...": "..." },
  "method": "publickey",
  "fingerprint": "SHA256:..."
}
```

Every request has `Content-Type: application/json`, plus `X-Forwarded-For`,
`X-Forwarded-Proto: ssh`, and `X-Forwarded-Host`. Cookies returned by the
backend are retained for the SSH connection and used for its filesystem
requests. Any non-`2xx` response rejects authentication.