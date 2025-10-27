#!/usr/bin/env node
import fs from "fs";
import path from "path";
import { execSync, execFileSync } from "child_process";
import process from "process";
import inquirer from "inquirer";
import gradient from "gradient-string";
import https from "https";

async function checkInternet() {
    return new Promise((resolve) => {
        const req = https.get("https://dumb-msg.xyz", (res) => {
            resolve(res.statusCode === 200);
        });

        req.on("error", () => resolve(false));
        req.setTimeout(3000, () => {
            req.destroy();
            resolve(false);
        });
    });
}

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
      type: "list",
      name: "email",
      message: "Enable email (Mailtrap):",
      choices: ["enable", "disable"],
      default: "enable"
    },
    {
      type: "list",
      name: "redis",
      message: "Enable Redis caching:",
      choices: ["enable", "disable"],
      default: "enable"
    },
    {
      type: "list",
      name: "proxy",
      message: "Enable proxy for external requests:",
      choices: ["enable", "disable"],
      default: "disable"
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
    const isOnline = await checkInternet();
    console.log(isOnline);
    let templatesPath = "temp_repo/templates";

    if (isOnline) {
        console.log("\n📥 Cloning repository from GitHub...");
        execSync("git clone https://github.com/dumbmessenger/dumb.git temp_repo", {stdio: "inherit"});
    } else {
        console.log("\n📍 Using local template folder")
        templatesPath = "templates/";
    }

    if (!fs.existsSync(templatesPath)) {
      console.log("❌ Templates folder not found in repository");
      process.exit(1);
    }

    console.log("📁 Creating project structure...");
    fs.mkdirSync(projectPath, { recursive: true });
    fs.mkdirSync(path.join(projectPath, "storage", "slaves"), { recursive: true });
    fs.mkdirSync(path.join(projectPath, "modules"), { recursive: true });

    console.log("📋 Copying template files...");
    
    const filesToCopy = [
      "server.js",
      "config.js",
      "dumix.js",
      "package.json"
    ];

    filesToCopy.forEach(file => {
      const src = path.join(templatesPath, file);
      const dest = path.join(projectPath, file);
      if (fs.existsSync(src)) {
        fs.copyFileSync(src, dest);
      }
    });

    const modulesSrcDir = path.join(templatesPath, "modules");
    if (fs.existsSync(modulesSrcDir)) {
      const moduleFiles = fs.readdirSync(modulesSrcDir);
      moduleFiles.forEach(file => {
        const src = path.join(modulesSrcDir, file);
        const dest = path.join(projectPath, "modules", file);
        fs.copyFileSync(src, dest);
      });
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
  email: {
    enabled: ${answers.email === "enable"},
    provider: 'mailtrap',
    mailtrap: {
      enabled: ${answers.email === "enable"},
      apiToken: process.env.MAILTRAP_API_TOKEN || 'd0d5ae5d37acdab32ba0618ed4c0b22b',
      fromEmail: process.env.SMTP_FROM_EMAIL || 'hello@dumb-msg.xyz',
      fromName: process.env.SMTP_FROM_NAME || 'Dumb Messenger',
      appUrl: process.env.APP_URL || 'http://localhost:${answers.port}'
    },
    smtp: {
      enabled: false,
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: process.env.SMTP_PORT || 587,
      secure: true,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      },
      fromEmail: process.env.SMTP_FROM_EMAIL || 'noreply@example.com',
      fromName: process.env.SMTP_FROM_NAME || 'Dumb Messenger',
      appUrl: process.env.APP_URL || 'http://localhost:${answers.port}'
    },
    firebase: {
      enabled: process.env.FIREBASE_ENABLED === 'false',
      serviceAccount: process.env.FIREBASE_SERVICE_ACCOUNT
    }
  },
  redis: {
    enabled: ${answers.redis === "enable"},
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    password: process.env.REDIS_PASSWORD,
    cache: {
      messagesTtl: 300,
      usersTtl: 600,
      channelsTtl: 900
    }
  },
  proxy: {
    enabled: ${answers.proxy === "enable"},
    rotationEnabled: false,
    rotationInterval: 30000,
    proxies: [
      {
        type: 'http',
        host: 'proxy.example.com',
        port: 8080,
        username: process.env.PROXY_USER,
        password: process.env.PROXY_PASS
      }
    ]
  },
  security: {
    passwordMinLength: 8,
    tokenTTL: 24 * 60 * 60 * 1000,
    pbkdf2: {
      iterations: 120000,
      keylen: 32,
      digest: "sha256"
    },
    encryptionKey: process.env.ENCRYPTION_KEY || "your-encryption-key",
    usernameRegex: /^[a-zA-Z0-9_-]{3,20}$/,
    maxMessageLength: 2000
  },
  storage: {
    type: "${answers.dbType}",
    file: "${answers.dbType === 'mysql' ? 'dumb_messenger' : 'db.json'}",
    ${answers.dbType === 'mysql' ? `
    mysql: {
      host: process.env.MYSQL_HOST || "localhost",
      port: process.env.MYSQL_PORT || 3306,
      user: process.env.MYSQL_USER || "root",
      password: process.env.MYSQL_PASSWORD || "",
      database: process.env.MYSQL_DATABASE || "dumbmessenger"
    }` : ''}
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
        dev: "node --watch server.js",
        plugins: "node -e \"import('./dumix.js').then(m => m.loadPlugins())\""
      },
      dependencies: {
        "@akaruineko1/anse2": "^0.1.0",
        "axios": "^1.12.2",
        "cors": "^2.8.5",
        "express": "^4.18.2",
        "form-data": "^4.0.4",
        "geoip-lite": "^1.4.10",
        "https-proxy-agent": "^7.0.6",
        "mailtrap": "^4.3.0",
        "multer": "^1.4.4",
        "mysql2": "^3.9.7",
        "nodemailer": "^7.0.10",
        "qrcode": "^1.5.4",
        "redis": "^5.8.3",
        "socks-proxy-agent": "^8.0.5",
        "speakeasy": "^2.0.0",
        "sql.js": "^1.8.0",
        "tunnel-ssh": "^5.2.0",
        "user-agents": "^1.1.669",
        "ws": "^8.17.0"
      }
    };
    
    fs.writeFileSync(
      path.join(projectPath, "package.json"), 
      JSON.stringify(packageJson, null, 2)
    );

    fs.mkdirSync(path.join(projectPath, "uploads"), { recursive: true });

    const envExample = `ENCRYPTION_KEY=your-secure-encryption-key-here
MAILTRAP_API_TOKEN=your_mailtrap_api_token_here
SMTP_FROM_EMAIL=hello@dumb-msg.xyz
SMTP_FROM_NAME=Dumb Messenger
APP_URL=http://localhost:${answers.port}
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=your_redis_password_here
${answers.proxy === "enable" ? `
PROXY_USER=your_proxy_username
PROXY_PASS=your_proxy_password` : ''}
${answers.dbType === 'mysql' ? `
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your_mysql_password
MYSQL_DATABASE=dumbmessenger` : ''}`;

    fs.writeFileSync(path.join(projectPath, ".env.example"), envExample);

    console.log("📦 Installing dependencies...");
    execSync("npm install", { cwd: projectPath, stdio: "inherit" });

    console.log("🧹 Cleaning up...");
    if (isOnline) {
      execSync("rm -rf temp_repo", { stdio: "inherit" });
    }

    console.log(gradient("green", "blue").multiline([
      "\n✅ DUMB Messenger installed successfully!",
      "",
      "📋 Next steps:",
      `1. cd ${answers.folder}`,
      "2. Copy .env.example to .env and configure your settings",
      "3. Configure your database (if using MySQL)",
      "4. Set MAILTRAP_API_TOKEN for email functionality",
      "5. npm start",
      "",
      "🌐 Your server will be available at:",
      `   http://localhost:${answers.port}`,
      "",
      "📧 Email: " + (answers.email === "enable" ? "Enabled with Mailtrap" : "Disabled"),
      "🗄️  Redis: " + (answers.redis === "enable" ? "Enabled for caching" : "Disabled"),
      "🔌 Proxy: " + (answers.proxy === "enable" ? "Enabled for external requests" : "Disabled"),
      "💾 Database: " + answers.dbType
    ]));

  } catch (err) {
    console.error("❌ Installation failed:", err);
    try { 
      if (fs.existsSync("temp_repo")) {
        execSync("rm -rf temp_repo"); 
      }
      if (fs.existsSync(projectPath)) {
        execFileSync("rm", ["-rf", projectPath]);
      }
    } catch {}
    process.exit(1);
  }
}

runInstaller();
