# Trivial Backend

This is a small HTTP application that authenticates a user, accepts drops, and
offers a set of pending downloads. The proxy owns SSH and SFTP; the backend
only speaks HTTP.

Configure the proxy to call one password endpoint:

```json
{
  "$schema": "./schemas/sftp-proxy.schema.json",
  "hostKeyFile": "/config/host_key",
  "authBackend": {
    "url": "http://backend.example.test:8080/auth"
  }
}
```

Use a backend address that the proxy can reach. This Hono app keeps pending
downloads in memory to make the flow visible; substitute storage where the
`Map` is used.

```js
import { serve } from "@hono/node-server";
import { Hono } from "hono";

const app = new Hono();
const origin = "http://backend.example.test:8080";
const pendingFiles = new Map([["welcome.txt", "Welcome.\n"]]);

function pendingChildren() {
  return [...pendingFiles.keys()].map((file) => ({
    file,
    backend: `${origin}/download/${encodeURIComponent(file)}`
  }));
}

app.post("/auth", async (context) => {
  const request = await context.req.json();
  if (request.connection?.username !== "acme" || request.password !== "secret") {
    return context.body(null, 403);
  }
  return context.json({
    user: {
      rootfs: {
        children: [
          {
            directory: "Inbound",
            backend: `${origin}/upload`,
            allowed_methods: ["POST"]
          },
          ...(pendingFiles.size ? [{
            directory: "Outbound",
            children: pendingChildren()
          }] : [])
        ]
      }
    }
  });
});

app.post("/upload/:name", (context) => {
  console.log("received", context.req.param("name"));
  return context.body(null, 200);
});

app.get("/download/:name", (context) => {
  const contents = pendingFiles.get(context.req.param("name"));
  return contents === undefined ? context.body(null, 404) : context.text(contents);
});
app.delete("/download/:name", (context) => {
  const removed = pendingFiles.delete(context.req.param("name"));
  return context.body(null, removed ? 200 : 404);
});

serve({ fetch: app.fetch, port: 8080, hostname: "0.0.0.0" });
```

Generate a host key, build the proxy image, and run it with the configuration
above. Start the Hono application where `backend.example.test:8080` resolves
from the proxy container.

```sh
ssh-keygen -t ed25519 -N '' -f host_key
docker build -t sftp-proxy .
docker run --rm --user 0 -p 2222:2222 \
  -v "$PWD/config.json:/config/config.json:ro" \
  -v "$PWD/host_key:/config/host_key:ro" \
  sftp-proxy
```

Connect with `sftp -P 2222 acme@localhost`. The short command uses root only
to read the bind-mounted host key; production deployments can keep the image's
default `sftpproxy` user when the key secret is readable by that user.

The flows are direct:

| SFTP action | Backend action |
| --- | --- |
| Upload `Inbound/order.csv` | `POST /upload/order.csv`; return `2xx` and do not add the file to a listing. `allowed_methods` prevents a listing request. |
| List `Outbound` | `seed.txt`-style entries come from the `children` returned by `/auth`; no outbound listing endpoint is needed. |
| Download `Outbound/welcome.txt` | `GET /download/welcome.txt`; return the file body. |
| Delete `Outbound/welcome.txt` | `DELETE /download/welcome.txt`; remove it from the pending set. |

The inline `Outbound` list is fixed for one SSH connection. A new connection
gets the current pending set. Move to [advanced backend support](advanced-backend.md)
when clients need an always-current listing or filesystem operations beyond
these three routes.