#!/usr/bin/env node
import fs from "fs";
import path from "path";
import { execSync, execFileSync } from "child_process";
import process from "process";
import inquirer from "inquirer";
import gradient from "gradient-string";
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function findTemplatesDir() {
  const possiblePaths = [
    path.join(__dirname, '..', 'templates'),
    path.join(__dirname, 'templates'),
    path.join(process.cwd(), 'node_modules', 'dpkgdumb', 'templates'),
    path.join(process.cwd(), 'node_modules', '.bin', '..', 'templates'),
    path.join(process.cwd(), 'templates')
  ];

  for (const templatePath of possiblePaths) {
    console.log(`🔍 Checking: ${templatePath}`);
    if (fs.existsSync(templatePath) && fs.existsSync(path.join(templatePath, 'server.js'))) {
      console.log(`✅ Found templates at: ${templatePath}`);
      return templatePath;
    }
  }
  
  return null;
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
    console.log("\n🔍 Looking for templates...");
    const packageTemplatesPath = findTemplatesDir();
    
    if (!packageTemplatesPath) {
      console.log("❌ Templates not found!");
      console.log("Tried paths:");
      console.log("- " + path.join(__dirname, '..', 'templates'));
      console.log("- " + path.join(__dirname, 'templates'));
      console.log("- " + path.join(process.cwd(), 'node_modules', 'dpkgdumb', 'templates'));
      console.log("\nPlease make sure the package is properly installed.");
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
      const src = path.join(packageTemplatesPath, file);
      const dest = path.join(projectPath, file);
      if (fs.existsSync(src)) {
        fs.copyFileSync(src, dest);
        console.log(`✅ Copied: ${file}`);
      } else {
        console.log(`⚠️  Warning: ${file} not found in templates`);
      }
    });

    const modulesSrcDir = path.join(packageTemplatesPath, "modules");
    if (fs.existsSync(modulesSrcDir)) {
      const moduleFiles = fs.readdirSync(modulesSrcDir);
      moduleFiles.forEach(file => {
        const src = path.join(modulesSrcDir, file);
        const dest = path.join(projectPath, "modules", file);
        fs.copyFileSync(src, dest);
        console.log(`✅ Copied module: ${file}`);
      });
    } else {
      console.log("⚠️  Warning: modules directory not found in templates");
    }

    const storageSrc = path.join(packageTemplatesPath, "storage", "storage.js");
    const storageDest = path.join(projectPath, "storage", "storage.js");
    if (fs.existsSync(storageSrc)) {
      fs.copyFileSync(storageSrc, storageDest);
      console.log("✅ Copied: storage/storage.js");
    } else {
      console.log("⚠️  Warning: storage.js not found in templates");
    }

    const slavesSrcDir = path.join(packageTemplatesPath, "storage", "slaves");
    if (fs.existsSync(slavesSrcDir)) {
      const slaveFiles = fs.readdirSync(slavesSrcDir);
      slaveFiles.forEach(file => {
        const src = path.join(slavesSrcDir, file);
        const dest = path.join(projectPath, "storage", "slaves", file);
        fs.copyFileSync(src, dest);
        console.log(`✅ Copied slave: ${file}`);
      });
    } else {
      console.log("⚠️  Warning: slaves directory not found in templates");
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
    provider: 'smtp',
    smtp: {
      enabled: ${answers.email === "enable"},
      useMailtrapAPI: true,
      apiToken: process.env.MAILTRAP_API || 'd0d5ae5d37acdab32ba0618ed4c0b22b',
      host: process.env.SMTP_HOST || 'send.api.mailtrap.io',
      port: process.env.SMTP_PORT || 443,
      secure: true,
      auth: {
        user: process.env.SMTP_USER || 'api',
        pass: process.env.SMTP_PASS || 'd0d5ae5d37acdab32ba0618ed4c0b22b'
      },
      fromEmail: process.env.SMTP_FROM_EMAIL || 'hello@dumb-msg.xyz',
      fromName: process.env.SMTP_FROM_NAME || 'Dumb Messenger'
    },
    firebase: {
      enabled: process.env.FIREBASE_ENABLED === 'false',
      serviceAccount: process.env.FIREBASE_SERVICE_ACCOUNT
    },
    appUrl: process.env.APP_URL || 'http://localhost:${answers.port}'
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
    mysql: {
      host: process.env.MYSQL_HOST || "localhost",
      port: process.env.MYSQL_PORT || 3306,
      user: process.env.MYSQL_USER || "root",
      password: process.env.MYSQL_PASSWORD || "",
      database: process.env.MYSQL_DATABASE || "dumbmessenger"
    }
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
      "name": "dumb-messenger",
      "version": "1.0.0",
      "type": "module",
      "scripts": {
        "start": "node server.js",
        "dev": "node --watch server.js",
        "plugins": "node -e \"import('./dumix.js').then(m => m.loadPlugins())\""
      },
      "dependencies": {
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
MAILTRAP_API=your_mailtrap_api_token_here
SMTP_HOST=send.api.mailtrap.io
SMTP_PORT=443
SMTP_USER=api
SMTP_PASS=your_mailtrap_api_token_here
SMTP_FROM_EMAIL=hello@dumb-msg.xyz
SMTP_FROM_NAME=Dumb Messenger
APP_URL=http://localhost:${answers.port}
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=your_redis_password_here
${answers.dbType === 'mysql' ? `
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your_mysql_password
MYSQL_DATABASE=dumbmessenger` : ''}
FIREBASE_ENABLED=false
FIREBASE_SERVICE_ACCOUNT=your_firebase_service_account_json_here`;

    fs.writeFileSync(path.join(projectPath, ".env.example"), envExample);

    console.log("📦 Installing dependencies with --legacy-peer-deps...");
    execSync("npm install --legacy-peer-deps", { cwd: projectPath, stdio: "inherit" });

    console.log(gradient("green", "blue").multiline([
      "\n✅ DUMB Messenger installed successfully!",
      "",
      "📋 Next steps:",
      `1. cd ${answers.folder}`,
      "2. Copy .env.example to .env and configure your settings",
      "3. Configure your database (if using MySQL)",
      "4. Set MAILTRAP_API for email functionality",
      "5. npm start",
      "",
      "🌐 Your server will be available at:",
      `   http://localhost:${answers.port}`,
      "",
      "📧 Email: " + (answers.email === "enable" ? "Enabled with Mailtrap API" : "Disabled"),
      "🗄️  Redis: " + (answers.redis === "enable" ? "Enabled for caching" : "Disabled"),
      "💾 Database: " + answers.dbType,
      "",
      "🔧 Used --legacy-peer-deps for package installation"
    ]));

  } catch (err) {
    console.error("❌ Installation failed:", err);
    try { 
      if (fs.existsSync(projectPath)) {
        execFileSync("rm", ["-rf", projectPath]);
      }
    } catch {}
    process.exit(1);
  }
}

runInstaller();
