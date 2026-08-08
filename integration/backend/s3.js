// A tenant directory served over HTTP whose listing hands the proxy the
// credentials for a bucket the proxy was never configured with. This is the
// multi-tenant shape: the backend that decides a user may see a bucket is also
// the one that can say how to reach it.
const http = require("http");

const origin = "http://backend-s3:8080";
const access = {
  region: "us-east-1",
  endpoint: process.env.S3_ENDPOINT,
  accessKeyId: process.env.S3_ACCESS_KEY_ID,
  secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
};

http.createServer((request, response) => {
  const url = new URL(request.url, origin);
  if (url.pathname !== "/tenant" || request.method !== "GET") {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, { "Content-Type": "application/vnd.sftpproxy.directory+json" });
  response.end(JSON.stringify({
    children: [
      { directory: "Archive", backend: "s3://tenant-42-archive/2026", s3: access },
      { directory: "ReadOnly", backend: "s3://tenant-42-archive/2026", s3: access, permissions: 0o555 },
    ],
  }));
}).listen(8080, "0.0.0.0");
