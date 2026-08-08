import { serve } from "@hono/node-server";
import { readFileSync } from "node:fs";
import { Hono } from "hono";

const app = new Hono();
const origin = "http://backend-pubkey:8080";
const seedContents = "public-key outbound seed\n";
const authorizedKey = readFileSync("/keys/acme.pub", "utf8").trim();

function authenticatedUser() {
  return {
    user: {
      rootfs: {
        children: [
          { directory: "Inbound", backend: `${origin}/upload`, allowedMethods: ["POST"] },
          {
            directory: "Outbound",
            children: [{ file: "seed.txt", backend: `${origin}/download/seed.txt` }]
          }
        ]
      }
    }
  };
}

app.post("/v1/sftp/auth/lookup", async (context) => {
  const request = await context.req.json();
  if (request.connection?.username !== "acme") {
    return context.body(null, 403);
  }
  return context.json({ methods: ["publickey"], authorizedKeys: [authorizedKey] });
});

app.post("/v1/sftp/auth/finalize", async (context) => {
  const request = await context.req.json();
  if (request.connection?.username !== "acme" || request.method !== "publickey") {
    return context.body(null, 403);
  }
  return context.json(authenticatedUser());
});

app.post("/upload/*", (context) => {
  console.log("upload", context.req.path);
  return context.body(null, 200);
});

app.get("/download/seed.txt", (context) => context.text(seedContents));
app.delete("/download/seed.txt", (context) => {
  console.log("delete", context.req.path);
  return context.body(null, 200);
});

serve({ fetch: app.fetch, port: 8080, hostname: "0.0.0.0" });