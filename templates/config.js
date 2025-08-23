export default {
  server: {
    host: "0.0.0.0",
    port: 3000
  },
  features: {
    http: true,
    ws: true,
    sse: true,
    voip: false,
    uploads: true
  },
  security: {
    passwordMinLength: 8,
    tokenTTL: 24 * 60 * 60 * 1000,
    pbkdf2: {
      iterations: 120000,
      keylen: 32,
      digest: "sha256"
    },
    maxMessageLength: 2000
  },
  storage: {
    type: "json",
    file: "db.json"
  },
  uploads: {
    dir: "uploads",
    maxFileSize: 2 * 1024 * 1024,
    allowedMime: ["image/png", "image/jpeg", "image/webp", "image/gif"]
  },
  cors: {
    origin: "*"
  },
  rateLimit: {
    windowMs: 60 * 1000,
    max: 60
  }
}
