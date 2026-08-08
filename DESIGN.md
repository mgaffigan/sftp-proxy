# SFTP to HTTP Proxy Design
A bulletproof SFTP to HTTP proxy that can serve as a front-end for a B2B interface.  We want to use the most widely deployed and tested libraries that we can, while avoiding unneccessary complexity (wireguard-style auditable code is best).

## V1 Implementation Contract

The server is implemented in Go, using `golang.org/x/crypto/ssh` for SSH and
`github.com/pkg/sftp` for SFTP. It supports SFTP and SCP over the same virtual
filesystem, served by an HTTP backend, a local filesystem backend, and an
S3-compatible object store backend.

The server uses a configured PEM host key and refuses to start if it cannot
load it. By default it listens on TCP port 2222 on IPv4 and IPv6 wildcard
addresses. It must fail startup rather than silently losing an address family.

### Configuration and Authentication

A static user is found by its SSH username and authenticates with a configured
password hash and/or configured authorized public keys. A static user does not
call the HTTP authentication backend.

Dynamic authentication is username-first, so a backend need only return the
policy for the requested user rather than every possible public key. The
dynamic flow has three phases:

1. `POST /v1/sftp/auth/lookup` receives the username and client connection
  metadata. It returns allowed authentication methods and, for public-key
  authentication, the public keys authorized for that username.
2. For password authentication, `POST /v1/sftp/auth/password` receives the
  username, password, and connection metadata. For public-key authentication,
  the proxy verifies the SSH signature locally using a key returned by lookup.
3. `POST /v1/sftp/auth/finalize` receives the username, authenticated method,
  and connection metadata. It returns the authenticated user configuration and
  virtual filesystem. The proxy calls finalize only after authentication has
  succeeded.

For a password-only integration, `authBackend.url` may instead name one
single-step endpoint. The proxy sends the username, password, method, and
connection metadata in one `POST`; a successful response returns the same user
configuration as finalize. This mode does not offer public-key authentication.

The backend may reject a request with a normal HTTP status code. `401` and
`403` reject authentication, `404` means the user is unknown, and `5xx` or a
malformed response fail the authentication attempt without exposing backend
details to the client. The exact JSON schemas are versioned by these endpoint
paths and must be documented beside the implementation.

Each SSH connection owns an HTTP cookie jar. It is reused for that connection's
authentication and filesystem requests only. The proxy adds `X-Forwarded-For`,
`X-Forwarded-Proto: ssh`, and `X-Forwarded-Host` when meaningful. Backend URLs
may use HTTP or HTTPS as configured. Redirects follow normal user-agent cookie
origin rules and must not escape the configured backend origin or path prefix.
Auth backends can provide headers that are propagated to HTTP and s3.

### HTTP Virtual Filesystem Contract

All configured backend URLs are base URLs. A child name is appended as one URL
path segment after validating it is a single relative filesystem component.
The proxy must reject absolute paths, traversal (`.` or `..`), NUL bytes, and
attempts to resolve outside the virtual root. It never exposes backend URLs to
the SFTP client.

`rootfs` is the root directory node and behaves as any other directory does. It
may carry a `backend`, its own `allowedMethods`, statically configured
`children`, or any combination. A root with a backend is listed by `GET`ting
that backend and is uploaded into by `POST`ing to a child of it, so clients can
work directly in `/` without a directory being configured first. A root with
only `children` serves them statically and, having no URL, accepts no uploads
of its own. As with any directory, a backend supersedes static children.

`GET` is used for directory listings and downloads. A successful directory
listing has content type `application/vnd.sftpproxy.directory+json` and the
documented `children` shape. Static configuration entries and entries returned
by a dynamic backend are homomorphic: both use the `entry` shape from the
configuration schema. A backend may therefore return `children`,
`allowedMethods`, `size`, `mtime`, `permissions`, and `maxUploadSize` on an entry, using the same field
names and shape as static configuration.

A successful file response is streamed to the client; `Content-Length`,
`Last-Modified`, and `ETag` provide synthetic SFTP metadata when present. Byte
offsets use RFC 9110 `Range` requests and responses are streamed rather than
buffered in memory.

A backend serving ranges must state the file's complete length in
`Content-Range`, on a `206` and on a `416` alike. That length is the only thing
that can be sent before a file is, so a backend which omits it or writes it as
`*` can be read over SFTP but not downloaded over SCP. A backend answering a
range request with the whole file is measured by staging it, which needs no
header at all.

Directory listing file entries may include a non-negative `size` field. The
proxy uses it as the synthetic SFTP file size so clients that stat before
reading, including OpenSSH, can transfer dynamic files correctly.

Entries may include an RFC 3339 `mtime` and numeric POSIX `permissions` bits
from `0` through `0777`. The proxy presents supplied values as SFTP metadata;
omitted values retain the synthetic defaults. On an HTTP entry that is all
`permissions` does; the local filesystem backend also enforces them.

Any entry, file or directory, may include `allowedMethods` with any of `GET`,
`POST`, and `DELETE`. It states which requests the proxy may send to that
entry's backend, so its purpose is to keep traffic off a backend that would
only refuse it: a directory excluding `GET` appears empty to SFTP clients with
no listing request made. It requires a `backend`, having nothing to constrain
without one, and is rejected rather than ignored on an entry that has none.

`allowedMethods` describes the entry that carries it and nothing else. It is
never inherited from a parent, never combined with an ancestor's, and never
consulted on one entry to decide an operation on another, so a writable file
may sit inside a read-only directory and a read-only file inside a writable
one. An entry that omits it permits every supported method, which means a
backend restricting a file must say so on that file. The single case where a
containing directory decides is creation: a path that does not exist yet has no
entry of its own, so `POST` on the directory that would contain it is the
permission to create within it.

It is not a permission model presented to clients. The backend remains the
authority on every request and answers `403`, `404`, or `405` as it sees fit;
the modes an SFTP client is shown describe only whether a node is a directory.

Files are uploaded by staging their SFTP writes in a private local directory.
On a successful close, the proxy sends the completed content as `POST` with
content type `application/octet-stream`. Aborted handles are discarded.
`maxUploadSize` is optional on a file or directory entry. On a file it rejects
writes beyond that file's limit; a backend creating a direct child of a
directory copies the directory's limit to that new file. The value is not
otherwise inherited. `maxConcurrentUploads` is an optional user configuration
value that limits uploads open at once on each of that user's SFTP connections;
when the count limit is reached, opening a new upload is rejected. Disk and
memory resource limits otherwise remain an operational responsibility of the
OS or container runtime.

An empty `POST` with content type
`application/vnd.sftpproxy.directoryentry` creates a directory. Plain `DELETE`
deletes either a file or directory; the backend determines the target type.
Rename is a `DELETE` to the source URL with a percent-encoded root-relative
`renameTo` query parameter. Being one `DELETE` on one entry, it is governed by
the source's `allowedMethods` alone. The proxy does not interpret the
destination beyond validating the path: whether a rename to it is possible,
including one that lands under a different backend, is the source backend's
answer to give. A backend is told where the source was as well as where it
should end up, which is nothing an HTTP backend needs; it is there for one that
must act on the destination itself and so must know what it is being asked.

HTTP `403` maps to an SFTP permission error, `404` to no-such-file, `405` to
operation-unsupported, and other non-success responses to a generic SFTP
failure unless a more specific safe mapping is documented. A `405` while
listing an upload-only directory is represented as an empty directory listing.

The proxy supports the standard SFTP data operations needed by ordinary
clients: list, stat, read, create, write, delete, rename, mkdir, and rmdir.
Permission, owner, group, and timestamp updates succeed as synthetic no-ops.
Operations requiring durable link semantics are unsupported until a backend
contract for them exists.

A rename onto an occupied name is an error rather than a replacement, as SFTP
says it is. Each backend asks its own store, the only thing that can answer;
neither can rename and refuse to clobber in one step, so an object arriving at
the destination in between is still replaced.

Opening a file to append is refused up front, before anything is created. A file
is staged from empty and stored whole, so appended writes would be all the
content there was rather than the end of it.

### Local Filesystem Backend

- **Paths**: Absolute local URLs only (no query, fragment, or remote host).
- **Prefixes**: Enabled via allowedPrefixes (absolute, non-nested).
- **Sandbox**: Locked to prefix; traversal (..) & symlink escapes blocked.
- **Permissions**: Masked via 'permissions' prop; inherits down tree.
- **Files**: Plain files/dirs only. Atomic uploads via temp renames.
- **Errors**: OS details hidden; generic backend errors, traces logged.

### S3 Backend

**Activation & Addressing**
The S3 backend is disabled by default; serving `s3://` URLs requires an explicit `s3Backend` configuration. Key paths are strictly literal names with no relative path climbing (`.` or `..`).

**Authentication & Credentials**
URLs never carry credentials. Authenticating buckets occurs via two paths:
* **Static Buckets (`s3Backend.buckets`)**: Use explicit credentials or ambient IAM (`useDefaultCredentials`). Ambient identity is disabled by default and resolved at startup; missing credentials cause an immediate startup failure.
* **Dynamic Entries**: Receive credentials (including short-lived STS tokens) via an `s3` property on the directory entry, which is inherited by all child nodes in the subtree. Dynamic entries cannot request `useDefaultCredentials` to prevent delegating the proxy's ambient identity.
* **Headers**: AWS transfer style metadata are included by default, and can be customized by an authentication backend.

**Directory Model & Permissions**
The backend exposes a virtual prefix tree: a directory is the prefix its members share. 0-byte markers are used for directories with no files. `permissions` is rejected on S3 nodes; instead, `allowedMethods` names the S3 API calls the proxy may make against a node — `ListObjectsV2`, `GetObject`, `PutObject`, `DeleteObject`, `CopyObject`.

### SCP

SCP arrives as an `exec` request rather than a subsystem, so a client runs
`scp -t` to upload or `scp -f` to download and the two sides then take turns.
Both directions are supported, with `-r` for whole trees and `-p` for
modification times; `-p` on an upload is a no-op, as a setstat is. An `exec`
request that is not an scp invocation is refused rather than answered with a
failing command: nothing else runs here, and there is no shell, so a quoted
remote path is unquoted by the proxy and a glob is a name rather than a pattern.

Paths are relative to the virtual root, which is also what `~` and `.` mean.
Uploading to a path that is a directory puts the file inside it under the name
the client gave; uploading to any other path writes that path, which is how
`scp local.txt host:remote.txt` renames on copy. Names arriving in the protocol
are validated as single path components rather than trusted, so a client cannot
steer a write outside the directory it named.

Every session ends by sending an exit status. A path that could not be
transferred is reported to the client in the protocol's own terms, the rest of a
recursive transfer continues, and the session's exit status is failure. Because
SCP states a file's length before sending it, and a `/` has no name to give a
client, a download of the root itself as a tree is unsupported.

## Server
The server should listen on IPv4+IPv6 on port 2222 on all interfaces unless otherwise configured.  

## Connection establishment
Once a connection is established, authentication should occur by first checking the configuration file for a configured user, then falling back to the configured HTTP backend URL.  

The request should be an HTTP POST containing the details of the client connection required for the backend to authorize and resolve the attempt to a user.  The backend should return the configuration for the user if authorized (with the same schema as might be configured in a configuration file statically), or an appropriate HTTP status code if unacceptable.

Authentication should be possible without the backend having special knowledge of the client protocol itself.  For example, if it is not commonly possible to evaluate public key authentication requests in an average HTTP backend, the proxy should handle the protocol-specific details and only send/request the necessary information to the backend.  As an example: this may mean that the proxy requests the backend perform authentication, and the backend reply that it cannot authenticate but provide the trusted public keys.  Subsequent requests would then be made with the proxy's assurance that the client has been authenticated according to the backend's policy.

During a connection, the SFTP proxy server acts as the user-agent for the backend.  This includes the accumulation of cookies.  The backend should also be sent X-Forwarded-For, X-Forwarded-Proto, and other headers as is appropriate for a reverse proxy.

## Virtual Filesystem

The proxy is layered so that each concern has one home. The server maps SFTP
onto filesystem operations and knows nothing of backend URLs. The virtual
filesystem owns paths, traversal, and which backend serves a node, and knows
nothing of SFTP or of any storage protocol. A backend serves exactly one
protocol and knows nothing of virtual paths or of traversal within them — a
backend whose protocol is the local filesystem still knows only where its own
URLs lead. Errors cross these boundaries as outcomes — not found, not permitted,
not supported, failed — so that no backend URL or remote message can reach a
client.

A node's backend URL scheme selects the backend serving it, which is what
allows one filesystem to mix them: a directory listing returned over HTTP may
name a child served from S3, and it is reached without any configuration
change. A deployment registers the schemes it permits, and one left
unregistered cannot be reached however an entry names it.

The virtual filesystem remembers where a path resolved to, so that repeated
work in a directory does not re-walk its ancestors. It never remembers what a
directory contained: listings and file metadata are fetched afresh every time,
and a rename or removal forgets the affected path together with everything
beneath it.

After a connection has been established, the configuration provided either statically or dynamically from the backend shall be used to construct the virtual filesystem specific to the authenticated user.  The filesystem may be backed by a combination of one of three sources:

1. Explicitly
1. From local storage
1. From an HTTP backend
1. From an S3-compatible backend

As an example, a config file or server may return for a user the following configuration:

```json
{
  "rootfs": {
    "children": [
      {
        "directory": "Inbound",
        "backend": "http://foo.bar.baz/blah/inbound"
      },
      {
        "directory": "Outbound",
        "backend": "http://foo.bar.baz/blah/outbound"
      },
      {
        "file": "README.md",
        "backend": "http://foo.bar.baz/blah/readme"
      },
      {
        "directory": "Archive",
        "children": [
          {
            "directory": "2026",
            "backend": "s3://foo.bar.baz/blah/archive/2026"
          }
        ]
      }
    ]
  }
}
```

When a client attempts to access a file or directory, the proxy should resolve the request against the virtual filesystem constructed for the authenticated user.  If the requested resource exists and the method is allowed, the proxy should forward the request to the appropriate backend.  If the resource does not exist or the method is not allowed, the proxy should return an appropriate error to the client.

The proxy should seek to minimize the number of interactions required, while allowing for dynamic behavior.  Complexity should be minimized (e.g.: not requiring the backend to support complex filesystem behaviors by masking them in the proxy iteself).  Where the backend supports byte-range requests (RFC 9110), it should be used.  Most transferred files will be less than 50 MB, but it should never be assumed that a file will fit into memory.

Backends may not support all HTTP methods or most filesystem behaviors.  Most backends likely only support either GET and POST.  Some might also support PUT and DELETE.

The proxy should handle standard user-agent behaviors like following redirects presented by the backend.  Cookies origins should be respected to avoid information disclosure.

### GET http://foo.bar.baz/blah/inbound
The server might return HTTP 405 Method Not Allowed since the directory only accepts uploads.  An empty directory listing should be returned to the client.  If a 403 Forbidden would be returned, the access denied should be communicated appropriately.

### POST http://foo.bar.baz/blah/inbound/Example%20file.txt
HTTP 200 OK if the upload is successful.

### GET http://foo.bar.baz/blah/inbound/Example%20file.txt 

HTTP 405 Method Not Allowed since the file can only be uploaded.  Or, if the file were found, 200 OK with the file contents would be returned.

### GET http://foo.bar.baz/blah/outbound
HTTP 200 OK with content-type `application/vnd.sftpproxy.directory+json` for a new directory listing.

```json
{
  "children": [
    {
      "directory": "Example Subdirectory",
      "children": [
        {
          "directory": "Nested Subdirectory",
          "children": [
            {
              "file": "Nested File.txt",
              "backend": "http://foo.bar.baz/blah/outbound/example-subdirectory/nested-subdirectory/nested-file.txt"
            }
          ]
        }
      ]
    },
    {
      "file": "Example File.txt",
      "backend": "http://foo.bar.baz/blah/outbound/example-file.txt"
    }
  ]
}
```

### DELETE http://foo.bar.baz/blah/outbound/Example%20file.txt
HTTP 200 OK if the deletion is successful, or other appropriate HTTP status code if not.

### DELETE http://foo.bar.baz/blah/outbound/Example%20file.txt?renameTo=%2Foutbound%2FNew%20Name.txt
HTTP 200 OK if the rename is successful, or other appropriate HTTP status code if not.

## Out of scope

- Complex filesystem behaviors on the backend (e.g., server-side symlinks, permissions, properties of files)

## General Considerations

- YAGNI
- Keep the proxy simple and avoid adding features that are not strictly necessary for the core functionality.
- Prioritize security and correctness over performance optimizations unless they are clearly beneficial.
- Avoid exposing sensitive information such as authentication credentials and backend URLs to unauthorized clients.
- Clean design will beat clever hacks.
