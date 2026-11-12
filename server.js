// Servidor relay: une al AGENTE (PC controlado) con el VISOR (navegador).
// - Sirve la página web del visor (carpeta public/).
// - El agente se registra con un ID y una contraseña.
// - El visor se conecta con ese ID + contraseña y el servidor reenvía:
//     imágenes de pantalla  agente -> visor   (binario JPEG)
//     mouse y teclado       visor  -> agente  (JSON)

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 8080;
const PUBLIC_DIR = path.join(__dirname, "public");

// id -> { ws, passHash, viewer, name }
const agents = new Map();
// Límite simple de intentos fallidos por IP (anti fuerza bruta)
const failures = new Map(); // ip -> { count, until }

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

const server = http.createServer((req, res) => {
  if (req.url === "/health") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("ok");
  }
  // Descarga del agente: sirve public/MiRemoto.exe, o redirige a DESCARGA_URL (p. ej. un Release de GitHub)
  if (req.url.split("?")[0] === "/descargar") {
    const exe = path.join(PUBLIC_DIR, "MiRemoto.exe");
    if (fs.existsSync(exe)) {
      res.writeHead(200, {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": 'attachment; filename="MiRemoto.exe"',
        "Content-Length": fs.statSync(exe).size,
      });
      return fs.createReadStream(exe).pipe(res);
    }
    if (process.env.DESCARGA_URL) {
      res.writeHead(302, { Location: process.env.DESCARGA_URL });
      return res.end();
    }
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    return res.end("El programa todavía no está disponible para descargar.");
  }
  let urlPath = decodeURIComponent(req.url.split("?")[0]);
  if (urlPath === "/") urlPath = "/index.html";
  const filePath = path.normalize(path.join(PUBLIC_DIR, urlPath));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end();
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      return res.end("No encontrado");
    }
    res.writeHead(200, { "Content-Type": MIME[path.extname(filePath)] || "application/octet-stream" });
    res.end(data);
  });
});

const wss = new WebSocketServer({ server, maxPayload: 8 * 1024 * 1024 });

const hash = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
const send = (ws, obj) => {
  if (ws && ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
};
const clientIp = (req) =>
  (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress;

function isBlocked(ip) {
  const f = failures.get(ip);
  return f && f.until > Date.now();
}
function registerFailure(ip) {
  const f = failures.get(ip) || { count: 0, until: 0 };
  f.count += 1;
  if (f.count >= 5) {
    f.until = Date.now() + 5 * 60 * 1000; // bloqueado 5 minutos
    f.count = 0;
  }
  failures.set(ip, f);
}

wss.on("connection", (ws, req) => {
  ws.isAlive = true;
  ws.on("pong", () => (ws.isAlive = true));
  ws.role = null;
  const ip = clientIp(req);

  ws.on("message", (data, isBinary) => {
    // ---------- Mensajes binarios: frames de pantalla del agente ----------
    if (isBinary) {
      if (ws.role === "agent") {
        const a = agents.get(ws.agentId);
        if (a && a.viewer && a.viewer.readyState === a.viewer.OPEN) {
          a.viewer.send(data, { binary: true });
        }
      }
      return;
    }

    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return;
    }

    // ---------- Registro del agente ----------
    if (msg.type === "register" && !ws.role) {
      const id = String(msg.id || "").replace(/\D/g, "");
      if (id.length < 6 || !msg.password) return send(ws, { type: "error", message: "Registro inválido" });
      const existing = agents.get(id);
      if (existing && existing.ws !== ws) {
        send(existing.ws, { type: "error", message: "Este ID se conectó desde otro lugar" });
        existing.ws.close();
      }
      ws.role = "agent";
      ws.agentId = id;
      agents.set(id, { ws, passHash: hash(msg.password), viewer: null, name: String(msg.name || "PC").slice(0, 60) });
      send(ws, { type: "registered", id });
      console.log(`[agente] conectado ${id}`);
      return;
    }

    // ---------- El agente cambia su contraseña ----------
    if (msg.type === "set-password" && ws.role === "agent") {
      const a = agents.get(ws.agentId);
      if (a && msg.password) a.passHash = hash(msg.password);
      return;
    }

    // ---------- El visor pide conectarse ----------
    if (msg.type === "connect" && !ws.role) {
      if (isBlocked(ip)) return send(ws, { type: "error", message: "Demasiados intentos. Espera 5 minutos." });
      const id = String(msg.id || "").replace(/\D/g, "");
      const a = agents.get(id);
      if (!a) return send(ws, { type: "error", message: "Ese ID no está en línea" });
      if (hash(msg.password || "") !== a.passHash) {
        registerFailure(ip);
        return send(ws, { type: "error", message: "Contraseña incorrecta" });
      }
      if (a.viewer && a.viewer.readyState === a.viewer.OPEN) {
        return send(ws, { type: "error", message: "Ese PC ya tiene una sesión activa" });
      }
      failures.delete(ip);
      ws.role = "viewer";
      ws.agentId = id;
      a.viewer = ws;
      send(ws, { type: "connected", id, name: a.name });
      send(a.ws, { type: "viewer-joined", ip });
      console.log(`[visor] ${ip} -> ${id}`);
      return;
    }

    // ---------- Reenvío entre visor y agente ----------
    const a = agents.get(ws.agentId);
    if (!a) return;
    if (ws.role === "viewer" && a.viewer === ws) {
      // input, ack, quality, etc.
      send(a.ws, msg);
    } else if (ws.role === "agent") {
      // info de pantalla, cortar sesión, etc.
      if (msg.type === "kick" && a.viewer) {
        send(a.viewer, { type: "error", message: "El otro PC cerró la sesión" });
        a.viewer.close();
        a.viewer = null;
        return;
      }
      send(a.viewer, msg);
    }
  });

  ws.on("close", () => {
    const a = agents.get(ws.agentId);
    if (!a) return;
    if (ws.role === "agent" && a.ws === ws) {
      if (a.viewer) {
        send(a.viewer, { type: "error", message: "El PC remoto se desconectó" });
        a.viewer.close();
      }
      agents.delete(ws.agentId);
      console.log(`[agente] desconectado ${ws.agentId}`);
    } else if (ws.role === "viewer" && a.viewer === ws) {
      a.viewer = null;
      send(a.ws, { type: "viewer-left" });
      console.log(`[visor] salió de ${ws.agentId}`);
    }
  });
});

// Ping cada 25 s: mantiene viva la conexión en hostings gratuitos y limpia conexiones muertas
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 25000);

server.listen(PORT, () => console.log(`Servidor listo en http://localhost:${PORT}`));
