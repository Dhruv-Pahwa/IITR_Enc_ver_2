// generate-key.js
const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

const out = path.join(__dirname, "secret.key");
if (fs.existsSync(out)) {
  console.log("secret.key already exists. Path:", out);
  process.exit(0);
}

const key = crypto.randomBytes(32);
fs.writeFileSync(out, key);
console.log("Generated secret.key (32 bytes) at", out);
console.log("Base64 key (for debugging/demo):", key.toString("base64"));
