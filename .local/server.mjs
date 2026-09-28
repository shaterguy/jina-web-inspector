import http from "node:http";
import { createMcpServer, SERVICE, VERSION, TOOL_NAMES } from "../src/server.mjs";

const port = Number(process.env.PORT || "17848");

async function bodyJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 262144) throw new Error("request body too large");
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

const app = http.createServer(async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, service: SERVICE, version: VERSION, transport: "streamable-http", loopback: true, read_only: true, required_secrets: [], upstream: "https://r.jina.ai", tools: TOOL_NAMES }));
    return;
  }
  if (req.method === "POST" && req.url === "/mcp") {
    try {
      const body = await bodyJson(req);
      const { server, transport } = createMcpServer();
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (error) {
      if (!res.headersSent) res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: String(error?.message || error) }));
    }
    return;
  }
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "not found" }));
});

app.listen(port, "127.0.0.1", () => console.log(`${SERVICE} listening on 127.0.0.1:${port}`));
