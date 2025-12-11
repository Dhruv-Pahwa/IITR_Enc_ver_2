// server.js
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bodyParser = require("body-parser");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// config
const PORT = process.env.PORT || 3000;
const KEY_PATH = path.join(__dirname, "secret.key");
const ALGORITHM = "aes-256-gcm";

// load key
if (!fs.existsSync(KEY_PATH)) {
  console.error("secret.key not found. Run: npm run genkey");
  process.exit(1);
}
const KEY = fs.readFileSync(KEY_PATH);
if (KEY.length !== 32) {
  console.error("secret.key must be 32 bytes.");
  process.exit(1);
}
console.log("Loaded AES-256 key (32 bytes).");

// middleware
app.use(bodyParser.json({ limit: "200mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ---- Demo-only: return base64 key so clients can import it (NOT secure in prod) ----
app.get("/get_key", (req, res) => {
  res.json({ key_base64: KEY.toString("base64") });
});

// ---- Server-side file encrypt & broadcast ----
function encryptBuffer(buffer) {
  const iv = crypto.randomBytes(12); // 12 bytes for GCM
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    iv: iv.toString("hex"),
    authTag: authTag.toString("hex"),
    content: ciphertext.toString("base64")
  };
}

function decryptPayload(payload) {
  const iv = Buffer.from(payload.iv, "hex");
  const authTag = Buffer.from(payload.authTag, "hex");
  const ciphertext = Buffer.from(payload.content, "base64");
  const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// upload-and-broadcast: accepts JSON {filename,filetype,filedata(base64)}
app.post("/upload-and-broadcast", (req, res) => {
  const { filename, filetype, filedata } = req.body;
  if (!filedata) return res.status(400).json({ message: "no filedata" });

  try {
    const buffer = Buffer.from(filedata, "base64");
    // server-side encrypt
    const encrypted = encryptBuffer(buffer);

    // broadcast to all clients
    io.emit("encrypted_broadcast", {
      filename,
      filetype,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
      content: encrypted.content
    });

    console.log(`[Server] Encrypted and broadcasted: ${filename}`);
    res.json({ status: "ok" });
  } catch (err) {
    console.error("upload error:", err);
    res.status(500).json({ message: "server error" });
  }
});

// decrypt-file: client posts {filename,filetype,iv,authTag,content,clientId}
// server decrypts and returns plaintext (attachment)
app.post("/decrypt-file", (req, res) => {
  try {
    const { filename, filetype, iv, authTag, content } = req.body;
    const plaintext = decryptPayload({ iv, authTag, content });
    res.writeHead(200, {
      "Content-Type": filetype || "application/octet-stream",
      "Content-Disposition": `attachment; filename="${filename}"`
    });
    res.end(plaintext);
  } catch (err) {
    console.error("decrypt-file error:", err);
    res.status(500).send("decrypt failed");
  }
});

// Socket.IO: relay streaming ciphertext and logs
io.on("connection", (socket) => {
  console.log("Client connected:", socket.id);
  // relay stream_chunk from a sender to other clients
  socket.on("stream_chunk", (data) => {
    // data: { iv (hex), ciphertext (base64), meta, ts }
    socket.broadcast.emit("stream_chunk", data);
  });

  socket.on("disconnect", () => {
    console.log("Client disconnected:", socket.id);
  });
});

server.listen(PORT, () => {
  console.log("Server running on http://localhost:" + PORT);
});
