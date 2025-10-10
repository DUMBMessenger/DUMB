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
    console.log("\n📥 Cloning repository from GitHub...");
    execSync("git clone https://github.com/dumbmessenger/dumb.git temp_repo", { stdio: "inherit" });
    
    const templatesPath = "temp_repo/templates";
    if (!fs.existsSync(templatesPath)) {
      console.log("❌ Templates folder not found in repository");
      process.exit(1);
    }

    console.log("📁 Creating project structure...");
    fs.mkdirSync(projectPath, { recursive: true });
    fs.mkdirSync(path.join(projectPath, "storage", "slaves"), { recursive: true });

    console.log("📋 Copying template files...");
    
    const serverSrc = path.join(templatesPath, "server.js");
    const serverDest = path.join(projectPath, "server.js");
    if (fs.existsSync(serverSrc)) {
      fs.copyFileSync(serverSrc, serverDest);
    }

    const storageSrc = path.join(templatesPath, "storage", "storage.js");
    const storageDest = path.join(projectPath, "storage", "storage.js");
    if (fs.existsSync(storageSrc)) {
      fs.copyFileSync(storageSrc, storageDest);
    }

    const slavesSrcDir = path.join(templatesPath, "storage", "slaves");
    if (fs.existsSync(slavesSrcDir)) {
      const slaveFiles = fs.readdirSync(slavesSrcDir);
      slaveFiles.forEach(file => {
        const src = path.join(slavesSrcDir, file);
        const dest = path.join(projectPath, "storage", "slaves", file);
        fs.copyFileSync(src, dest);
      });
    }

    console.log("⚙️  Creating configuration...");
    const configContent = `export default {
  github: {
    owner: "dumbmessenger",
    repo: "dumb"
  },
  npm: {
    packageName: "dpkgdumb"
  },
  server: {
    host: "0.0.0.0",
    port: ${answers.port}
  },
  features: {
    http: true,
    ws: ${answers.websocket === "enable"},
    sse: ${answers.sse === "enable"},
    voip: ${answers.voip === "enable"},
    uploads: ${answers.uploads === "enable"},
    webRTC: ${answers.voip === "enable"},
    twoFactor: true,
    voiceMessages: true
  },
  security: {
    passwordMinLength: 8,
    tokenTTL: 24 * 60 * 60 * 1000,
    pbkdf2: {
      iterations: 120000,
      keylen: 32,
      digest: "sha256"
    },
    encryptionKey: process.env.ENCRYPTION_KEY || "your-default-encryption-key-change-in-production",
    usernameRegex: /^[a-zA-Z0-9_-]{3,20}$/,
    maxMessageLength: 2000
  },
  storage: {
    type: "${answers.dbType}",
    file: "${answers.dbType === 'mysql' ? 'dumb_messenger' : 'db.sqlite'}",
    ${answers.dbType === 'mysql' ? `
    host: "localhost",
    port: 3306,
    user: "root",
    password: "",
    database: "dumb_messenger"` : ''}
  },
  uploads: {
    dir: "uploads",
    maxFileSize: 10 * 1024 * 1024,
    allowedMime: ["image/png", "image/jpeg", "image/webp", "image/gif", "audio/ogg", "audio/wav", "audio/mpeg"]
  },
  cors: {
    origin: "*"
  },
  rateLimit: {
    windowMs: 60 * 1000,
    max: 60
  },
  ws: {
    port: ${parseInt(answers.port) + 1}
  }
};`;

    fs.writeFileSync(path.join(projectPath, "config.js"), configContent);

    console.log("📦 Creating package.json...");
    const packageJson = {
      name: "dumb-messenger",
      version: "1.0.0",
      type: "module",
      scripts: {
        start: "node server.js",
        dev: "node --watch server.js"
      },
      dependencies: {
        express: "^4.18.2",
        ws: "^8.17.0",
        "sql.js": "^1.8.0",
        "mysql2": "^3.9.7",
        multer: "^1.4.4",
        cors: "^2.8.5",
        qrcode: "^1.5.4",
        speakeasy: "^2.0.0"
      }
    };
    
    fs.writeFileSync(
      path.join(projectPath, "package.json"), 
      JSON.stringify(packageJson, null, 2)
    );

    fs.mkdirSync(path.join(projectPath, "uploads"), { recursive: true });

    const envExample = `ENCRYPTION_KEY=your-secure-encryption-key-here
${answers.dbType === 'mysql' ? `
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your-mysql-password
DB_NAME=dumb_messenger` : ''}`;

    fs.writeFileSync(path.join(projectPath, ".env.example"), envExample);

    console.log("📦 Installing dependencies...");
    execSync("npm install", { cwd: projectPath, stdio: "inherit" });

    console.log("🧹 Cleaning up...");
    execSync("rm -rf temp_repo", { stdio: "inherit" });

    console.log(gradient("green", "blue").multiline([
      "\n✅ DUMB Messenger installed successfully!",
      "",
      "📋 Next steps:",
      `1. cd ${answers.folder}`,
      "2. Configure your database (if using MySQL)",
      "3. Set ENCRYPTION_KEY in environment variables",
      "4. npm start",
      "",
      "🌐 Your server will be available at:",
      `   http://localhost:${answers.port}`
    ]));

  } catch (err) {
    console.error("❌ Installation failed:", err);
    try { 
      execSync("rm -rf temp_repo"); 
      if (fs.existsSync(projectPath)) {
        execSync(`rm -rf ${projectPath}`);
      }
    } catch {}
    process.exit(1);
  }
}

runInstaller();
