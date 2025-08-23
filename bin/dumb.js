#!/usr/bin/env node
import fs from "fs";
import path from "path";
import inquirer from "inquirer";
import gradient from "gradient-string";
import { fileURLToPath } from "url";
import { execSync } from "child_process";
import process from "process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function clearConsole() {
  process.stdout.write("\x1Bc");
}

function copyTemplate(filename, targetDir) {
  const src = path.join(__dirname, "../templates", filename);
  const dest = path.join(targetDir, filename);
  fs.copyFileSync(src, dest);
}

async function askQuestions() {
  const questions = [
    {
      type: "list",
      name: "db",
      message: "Select database (where messenger data will be stored):",
      choices: ["json", "sqlite", "mysql"],
      default: "json"
    },
    {
      type: "list",
      name: "ws",
      message: "Enable WebSocket (for real-time and VoIP signaling)?",
      choices: ["enable", "disable"],
      default: "enable"
    },
    {
      type: "list",
      name: "sse",
      message: "Enable Server-Sent Events (lightweight one-way streaming)?",
      choices: ["enable", "disable"],
      default: "disable"
    },
    {
      type: "list",
      name: "voip",
      message: "Enable VoIP (WebRTC signaling)?",
      choices: ["enable", "disable"],
      default: "disable"
    },
    {
      type: "list",
      name: "uploads",
      message: "Enable file uploads (files, avatars)?",
      choices: ["enable", "disable"],
      default: "enable"
    },
    {
      type: "input",
      name: "port",
      message: "Server port (where it will listen):",
      default: "3000",
      validate: input => /^\d+$/.test(input) ? true : "Please enter a valid port number"
    }
  ];

  return inquirer.prompt(questions);
}

async function runInstaller() {
  clearConsole();
  console.log(gradient("cyan", "magenta").multiline([
    "──────────────────────────────",
    "   DUMB Installer v2",
    "──────────────────────────────\n"
  ]));

  let answers;
  try {
    answers = await askQuestions();
  } catch (err) {
    console.error("❌ Prompt failed:", err);
    process.exit(1);
  }

  const config = {
    server: {
      host: "0.0.0.0",
      port: parseInt(answers.port, 10),
      protocols: {
        http: true,
        websocket: answers.ws === "enable",
        sse: answers.sse === "enable"
      }
    },
    db: answers.db,
    features: {
      ws: answers.ws === "enable",
      sse: answers.sse === "enable",
      voip: answers.voip === "enable",
      uploads: answers.uploads === "enable"
    },
    client: {
      web: {
        enabled: false,
        sourceUrl: "",
        targetDir: "public"
      }
    }
  };

  const projectPath = path.join(process.cwd(), "DUMB");
  if (!fs.existsSync(projectPath)) fs.mkdirSync(projectPath);

  // Copy server and storage templates
  ["server.js", "storage.js"].forEach(file => copyTemplate(file, projectPath));

  // Write config.js
  const cfgFile = path.join(projectPath, "config.js");
  fs.writeFileSync(cfgFile, `export default ${JSON.stringify(config, null, 2)}\n`);

  // Write package.json
  const pkg = {
    name: "dumb-server",
    version: "2.0.0",
    type: "module",
    scripts: { start: "node server.js" },
    dependencies: {
      express: "^4.18.2",
      ws: "^8.17.0",
     "sql.js": "^1.9.0",
      mysql2: "^3.9.7",
      multer: "1.4.4",
      cors: "^2.8.5"
    }
  };
  fs.writeFileSync(path.join(projectPath, "package.json"), JSON.stringify(pkg, null, 2));

  console.log("\n📦 Installing dependencies...\n");
  try {
    execSync("npm install", { cwd: projectPath, stdio: "inherit" });
  } catch (err) {
    console.error("❌ npm install failed:", err);
    process.exit(1);
  }

  console.log("\n✅ Setup complete!\n  cd DUMB && npm start\n");
}

runInstaller();
