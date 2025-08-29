#!/usr/bin/env node
import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import process from "process";
import inquirer from "inquirer";
import gradient from "gradient-string";

async function runInstaller() {
  console.log(gradient("cyan", "magenta").multiline([
    "   DUMB Messenger Installer"
  ]));

  const answers = await inquirer.prompt([
    {
      type: "list",
      name: "dbType",
      message: "Select database type:",
      choices: ["json", "sqlite", "mysql"],
      default: "json"
    },
    {
      type: "list",
      name: "websocket",
      message: "Enable WebSocket (real-time messaging):",
      choices: ["enable", "disable"],
      default: "enable"
    },
    {
      type: "list",
      name: "sse",
      message: "Enable Server-Sent Events:",
      choices: ["enable", "disable"],
      default: "disable"
    },
    {
      type: "list",
      name: "voip",
      message: "Enable VoIP (WebRTC signaling):",
      choices: ["enable", "disable"],
      default: "enable"
    },
    {
      type: "list",
      name: "uploads",
      message: "Enable file uploads:",
      choices: ["enable", "disable"],
      default: "enable"
    },
    {
      type: "input",
      name: "port",
      message: "Server port:",
      default: "3000",
      validate: input => /^\d+$/.test(input) ? true : "Please enter a valid port number"
    },
    {
      type: "input",
      name: "folder",
      message: "Installation folder:",
      default: "dumb-messenger"
    }
  ]);

  const projectPath = path.join(process.cwd(), answers.folder);
  
  if (fs.existsSync(projectPath)) {
    console.log("❌ Folder already exists. Please choose another name.");
    process.exit(1);
  }

  try {
    console.log("\n📥 Downloading files from GitHub...");
    
    const files = [
      'server.js',
      'storage/storage.js', 
      'storage/slaves/json.js',
      'storage/slaves/sqls.js'
    ];

    console.log("📁 Creating project structure...");
    fs.mkdirSync(projectPath, { recursive: true });
    fs.mkdirSync(path.join(projectPath, "storage", "slaves"), { recursive: true });

    console.log("📋 Downloading individual files...");
    
    for (const file of files) {
      const url = `https://raw.githubusercontent.com/debianrose/dumb/main/${file}`;
      const dest = path.join(projectPath, file);
      
      try {
        execSync(`curl -s -o "${dest}" "${url}"`, { stdio: 'inherit' });
        console.log(`✅ Downloaded: ${file}`);
      } catch (error) {
        console.log(`⚠️  Failed to download: ${file}`);
      }
    }

    console.log("⚙️  Creating configuration...");
    const configContent = `export default {
  server: {
    host: "0.0.0.0",
    port: ${answers.port}
  },
  features: {
    http: true,
    ws: ${answers.websocket === "enable"},
    sse: ${answers.sse === "enable"},
    voip: ${answers.voip === "enable"},
    uploads: ${answers.uploads === "enable"}
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
    type: "${answers.dbType}",
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
}`;

    fs.writeFileSync(path.join(projectPath, "config.js"), configContent);

    console.log("📦 Installing dependencies...");
    const packageJson = {
      name: "dumb-messenger",
      version: "1.0.0",
      type: "module",
      scripts: { start: "node server.js" },
      dependencies: {
        express: "^4.18.2",
        ws: "^8.17.0",
        "sql.js": "^1.9.0",
        mysql2: "^3.9.7",
        multer: "^1.4.4",
        cors: "^2.8.5"
      }
    };
    
    fs.writeFileSync(
      path.join(projectPath, "package.json"), 
      JSON.stringify(packageJson, null, 2)
    );

    execSync("npm install", { cwd: projectPath, stdio: "inherit" });

    console.log(gradient("magneta", "cyan").multiline([
      "\n✅ Installation complete!",
      "──────────────────────────────",
      `📁 Folder: ${answers.folder}`,
      `🌐 Port: ${answers.port}`,
      `🗄️  Database: ${answers.dbType}`,
      `🔌 WebSocket: ${answers.websocket}`,
      `📡 SSE: ${answers.sse}`,
      `📞 VoIP: ${answers.voip}`,
      `📁 Uploads: ${answers.uploads}`,
      "──────────────────────────────",
      "🚀 To start the server:",
      `   cd ${answers.folder}`,
      "   npm start",
      "──────────────────────────────\n"
    ]));

  } catch (err) {
    console.error("❌ Installation failed:", err);
    process.exit(1);
  }
}

runInstaller();
