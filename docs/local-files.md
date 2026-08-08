# Local Files

Use this when the files a partner uploads and collects already live on disk, or
should. No HTTP backend is involved; the proxy reads and writes the directories
you name and nothing else.

## Consent Comes First

The proxy will not serve a local path it was not given. List the directories it
may serve in `fileBackend.allowedPrefixes`, and every `file://` URL elsewhere in
the configuration must name a POSIX absolute path inside one of them:

```json
{
  "$schema": "./schemas/sftp-proxy.schema.json",
  "hostKeyFile": "/config/host_key",
  "fileBackend": {
    "allowedPrefixes": ["/srv/sftp/acme"]
  },
  "users": [
    {
      "username": "acme",
      "passwordHash": "$2a$12$CftPk3E1S3CJ4lnPavA1/.fw.FTIn4jwgHd13aqZ693MMJEvFUmT.",
      "rootfs": {
        "children": [
          {
            "directory": "Inbound",
            "backend": "file:///srv/sftp/acme/inbound",
            "permissions": 219
          },
          {
            "directory": "Outbound",
            "backend": "file:///srv/sftp/acme/outbound",
            "permissions": 365
          }
        ]
      }
    }
  ]
}
```

The example hash is for the password `password`; generate your own with
`docker run --rm -it sftp-proxy -hash-password`.

Each prefix must be an absolute, cleaned path and must exist when the proxy
starts; one that does not is a startup failure rather than a directory that
quietly serves nothing. No prefix may contain another. A `file://` URL outside
every prefix fails startup too, so a configuration mistake is reported before a
client can find it.

Leave `fileBackend` out and the scheme is not available at all: a `file://` URL
anywhere in a configuration, or in a directory listing an HTTP backend returns,
cannot be reached.

Nothing outside a prefix is reachable at run time either. Every operation names
its target relative to the prefix it was found under, so a path cannot climb out
with `..` and a symbolic link cannot point out. Links are not served in any
case: only plain files and directories appear in a listing.

## Permissions Are The Lever

`permissions` is a mask over what the filesystem already allows. Any read bit
permits reading and listing; any write bit permits uploading, renaming, deleting,
and creating directories. Above, `0333` makes `Inbound` a drop box — a client
uploads into it but sees it as empty — and `0555` makes `Outbound` readable and
nothing more. JSON has no octal literals, so write the decimal value your editor
shows for the mode you mean: `0333` is `219`, `0555` is `365`, `0755` is `493`.

A mask only ever takes permission away. The proxy cannot grant what the uid it
runs as does not already have, so the filesystem stays the outer bound and the
mask is what you tighten inside it.

The mask is inherited. A directory's mask narrows what is listed inside it, and
that in turn narrows what is inside that, so marking `Outbound` read-only makes
the whole tree beneath it read-only without repeating yourself. `allowedMethods`
belongs to HTTP backends and is rejected on a `file://` entry — this is what to
use instead.

## Uploads

An upload is written under a hidden name beside the one the client chose and
renamed over it when the transfer completes, so a process watching the directory
never sees a partial file and an abandoned transfer leaves whatever was already
there untouched. Renaming is otherwise supported only within one directory, which
is what a client that uploads under a temporary name and moves it into place
needs.

Uploaded files are created `0666` and directories `0777`, narrowed by the
process umask, as any other tool on the host would. Set the umask on the service
if a consuming process needs something narrower:

```sh
docker run --rm --user 0 -p 2222:2222 \
  -v "$PWD/config.json:/config/config.json:ro" \
  -v "$PWD/host_key:/config/host_key:ro" \
  -v /srv/sftp/acme:/srv/sftp/acme \
  --entrypoint /bin/sh sftp-proxy \
  -c 'umask 007 && exec /usr/local/bin/sftp-proxy -config /config/config.json'
```

The directories must be readable and writable by the uid the proxy runs as. The
example command runs as root only to read a bind-mounted host key; a deployed
service should keep the image's `sftpproxy` user and own its directories.

## Mixing With An HTTP Backend

A local directory is an ordinary node, so one filesystem can hold both:

```json
{
  "rootfs": {
    "children": [
      { "directory": "Inbound", "backend": "https://files.example.com/inbound" },
      { "directory": "Archive", "backend": "file:///srv/sftp/acme/archive", "permissions": 365 }
    ]
  }
}
```

The same holds for a user configuration an authentication backend returns, with
one difference: only a statically configured path can be checked at startup, so a
dynamic one outside every allowed prefix is refused when a client reaches for it.
