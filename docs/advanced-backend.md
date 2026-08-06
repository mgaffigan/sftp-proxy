# Advanced Backend Support

Start here after the [trivial backend](trivial-backend.md) flow is working.
Give a directory its own backend URL when clients need a current listing:

```json
{
  "directory": "Outbound",
  "backend": "https://files.example.com/outbound"
}
```

On `GET /outbound`, return the directory media type and one entry per child.
Include `size` for files so SFTP clients that stat before downloading know when
to stop:

```http
Content-Type: application/vnd.sftproxy.directory+json
```

```json
{
  "children": [
    {
      "file": "invoice.csv",
      "size": 42,
      "backend": "https://files.example.com/outbound/invoice.csv"
    },
    {
      "directory": "Archive",
      "backend": "https://files.example.com/outbound/archive"
    }
  ]
}
```

Serve a file URL with HTTP byte ranges. For a request such as
`Range: bytes=32768-65535`, return `206`, `Content-Range`, and the requested
bytes. Return `416` when the range starts after the final byte. A normal `200`
response is also accepted; the proxy stages that file once per open SFTP handle
to provide random access.

These operations fill out the rest of an ordinary SFTP workflow:

| SFTP action | HTTP request |
| --- | --- |
| Refresh a directory | `GET` the directory backend; return the listing document above. |
| Upload a file | `POST` its file URL with `Content-Type: application/octet-stream`. |
| Delete a file or empty directory | `DELETE` its backend URL. |
| Rename | `DELETE` the source URL with `renameTo` set to the percent-encoded root-relative destination, such as `%2FOutbound%2Fpaid.csv`. |
| Create a directory | Empty `POST` to the new directory URL with `Content-Type: application/vnd.sftpproxy.directoryentry`. |

Return `403` for denied access, `404` for absent files, and `405` for an
unsupported operation. The proxy maps those statuses to the matching SFTP
result.