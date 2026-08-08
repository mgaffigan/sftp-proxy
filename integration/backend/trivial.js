import { serve } from "@hono/node-server";
import { Hono } from "hono";

const app = new Hono();
const origin = "http://backend-trivial:8080";
const seedContents = "trivial outbound seed\n";
const sharedSecret = "Bearer integration-test-secret";

app.post("/auth", async (context) => {
  if (context.req.header("authorization") !== sharedSecret) {
    return context.body(null, 403);
  }
  const credentials = await context.req.json();
  if (credentials.connection?.username !== "acme" || credentials.password !== "secret") {
    return context.body(null, 403);
  }

  return context.json({
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
  });
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