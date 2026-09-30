/* Server locale per provare l'app senza Netlify: file statici da public/ e /api/* sulla stessa logica delle Functions.
   Uso: TEST_DATABASE_URL=postgres://... JWT_SECRET=... node --experimental-strip-types test/dev-server.mts */
import http from "node:http";
import pg from "pg";
import { readFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { setPool } from "../netlify/lib/db.mts";
import { handle } from "../netlify/lib/app.mts";

const pool = new pg.Pool({ connectionString: process.env.TEST_DATABASE_URL });
if (process.env.RESET_DB) {
  await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
  await pool.query(readFileSync(new URL("../netlify/database/migrations/001_schema/migration.sql", import.meta.url), "utf8"));
}
setPool(pool as any);
const port = Number(process.env.PORT || 8888);

http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://localhost:${port}`);
  if (url.pathname.startsWith("/api/")) {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const r = await handle(new Request(url, {
      method: req.method, headers: req.headers as any,
      body: ["GET", "HEAD"].includes(req.method || "") ? undefined : Buffer.concat(chunks),
    }), req.socket.remoteAddress || "");
    const h: Record<string, string> = {};
    r.headers.forEach((v, k) => (h[k] = v));
    res.writeHead(r.status, h).end(Buffer.from(await r.arrayBuffer()));
    return;
  }
  try {
    const f = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
    if (f.includes("..")) throw 0;
    const body = await readFile(new URL("../public/" + f, import.meta.url));
    res.writeHead(200, { "content-type": f.endsWith(".html") ? "text/html; charset=utf-8" : "application/octet-stream" }).end(body);
  } catch { res.writeHead(404).end("Not found"); }
}).listen(port, () => console.log("http://localhost:" + port));
