const http = require("http");

const files = new Map([["/seed.txt", Buffer.from("seed data\n")]]);
const directories = new Set(["/"]);
const origin = "http://backend-full:8080";

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function backendPath(pathname) {
  const value = decodeURIComponent(pathname.slice("/fs".length)) || "/";
  return value.startsWith("/") ? value : `/${value}`;
}

function parent(name) {
  const slash = name.lastIndexOf("/");
  return slash === 0 ? "/" : name.slice(0, slash);
}

function childEntries(directory) {
  const names = [];
  for (const name of directories) {
    if (name !== directory && parent(name) === directory) {
      names.push({ directory: name.slice(name.lastIndexOf("/") + 1), backend: `${origin}/fs${name}` });
    }
  }
  for (const name of files.keys()) {
    if (parent(name) === directory) {
      names.push({ file: name.slice(name.lastIndexOf("/") + 1), size: files.get(name).length, backend: `${origin}/fs${name}` });
    }
  }
  return names.sort((left, right) => (left.directory || left.file).localeCompare(right.directory || right.file));
}

function renameTarget(value) {
  if (!value.startsWith("/Workspace/")) return null;
  return value.slice("/Workspace".length);
}

http.createServer(async (request, response) => {
  const url = new URL(request.url, origin);
  if (url.pathname === "/auth" && request.method === "POST") {
    const credentials = JSON.parse((await readBody(request)).toString("utf8"));
    if (credentials.connection?.username !== "acme" || credentials.password !== "secret") {
      response.writeHead(403).end();
      return;
    }
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ user: { rootfs: { children: [{ directory: "Workspace", backend: `${origin}/fs` }] } } }));
    return;
  }
  if (!url.pathname.startsWith("/fs")) {
    response.writeHead(404).end();
    return;
  }

  const path = backendPath(url.pathname);
  if (request.method === "GET" && directories.has(path)) {
    response.writeHead(200, { "Content-Type": "application/vnd.sftproxy.directory+json" });
    response.end(JSON.stringify({ children: childEntries(path) }));
    return;
  }
  if (request.method === "GET" && files.has(path)) {
    const contents = files.get(path);
    const range = request.headers.range?.match(/^bytes=(\d+)-(\d+)$/);
    if (range) {
      const start = Number(range[1]);
      if (start >= contents.length) {
        response.writeHead(416, { "Content-Range": `bytes */${contents.length}` });
        response.end();
        return;
      }
      const end = Math.min(Number(range[2]), contents.length - 1);
      response.writeHead(206, { "Content-Range": `bytes ${start}-${end}/${contents.length}`, "Content-Length": end - start + 1 });
      response.end(contents.subarray(start, end + 1));
      return;
    }
    response.writeHead(200, { "Content-Length": contents.length });
    response.end(contents);
    return;
  }
  if (request.method === "POST" && request.headers["content-type"] === "application/vnd.sftpproxy.directoryentry") {
    if (!directories.has(parent(path))) {
      response.writeHead(404).end();
      return;
    }
    directories.add(path);
    response.writeHead(200).end();
    return;
  }
  if (request.method === "POST") {
    if (!directories.has(parent(path))) {
      response.writeHead(404).end();
      return;
    }
    files.set(path, await readBody(request));
    response.writeHead(200).end();
    return;
  }
  if (request.method === "DELETE" && url.searchParams.has("renameTo")) {
    const target = renameTarget(url.searchParams.get("renameTo"));
    if (!target || !files.has(path) || !directories.has(parent(target))) {
      response.writeHead(404).end();
      return;
    }
    files.set(target, files.get(path));
    files.delete(path);
    response.writeHead(200).end();
    return;
  }
  if (request.method === "DELETE" && files.has(path)) {
    files.delete(path);
    response.writeHead(200).end();
    return;
  }
  if (request.method === "DELETE" && directories.has(path) && childEntries(path).length === 0) {
    directories.delete(path);
    response.writeHead(200).end();
    return;
  }
  response.writeHead(404).end();
}).listen(8080, "0.0.0.0");