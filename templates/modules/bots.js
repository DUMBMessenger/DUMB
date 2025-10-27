export class BotSystem {
  constructor(storage, websocketServer) {
    this.storage = storage;
    this._wss = websocketServer;
    this.bots = new Map();
    this.botUsers = new Set();
  }

  set wss(websocketServer) {
    this._wss = websocketServer;
  }

  get wss() {
    return this._wss;
  }

  async registerBot(username, owner, webhookUrl = null) {
    const ownerExists = await this.storage.authenticate(owner, 'dummy');
    if (!ownerExists) {
      throw new Error('Owner does not exist');
    }

    const botToken = await this.createBotAccount(username, owner);
    
    const bot = {
      username,
      owner,
      webhookUrl,
      token: botToken,
      createdAt: Date.now(),
      active: true,
      permissions: ['read_messages', 'send_messages']
    };

    this.bots.set(username, bot);
    this.botUsers.add(username);

    return bot;
  }

  async createBotAccount(username, owner) {
    const crypto = require('crypto');
    const password = crypto.randomBytes(32).toString('hex');
    
    await this.storage.registerUser(username, password);
    
    const token = crypto.randomBytes(32).toString('hex');
    await this.storage.saveToken(username, token, Date.now() + 365 * 24 * 60 * 60 * 1000);
    
    await this.storage.setUserType(username, 'bot');

    return token;
  }

  async processMessageForBots(message) {
    for (const [botUsername, bot] of this.bots) {
      if (bot.active && bot.webhookUrl) {
        this.sendWebhook(bot, message);
      }

      if (this.isBotCommand(message.text, botUsername)) {
        await this.handleBotCommand(bot, message);
      }
    }
  }

  isBotCommand(text, botUsername) {
    if (!text) return false;
    return text.trim().startsWith(`@${botUsername}`) || 
           text.trim().startsWith(`/bot ${botUsername}`);
  }

  async handleBotCommand(bot, message) {
    const response = await this.executeBotCommand(bot, message);
    
    if (response) {
      await this.sendBotMessage(bot.username, message.channel, response);
    }
  }

  async sendBotMessage(botUsername, channel, text) {
    const msg = {
      from: botUsername,
      channel: channel,
      text: text,
      ts: Date.now(),
      bot: true
    };

    const saved = await this.storage.saveMessage(msg);
    
    if (this._wss) {
      this._wss.broadcast({
        ...saved,
        type: "message",
        action: "new"
      });
    }

    return saved;
  }

  async executeBotCommand(bot, message) {
    const command = message.text.toLowerCase();
    
    if (command.includes('help')) {
      return `Я бот ${bot.username}. Доступные команды: help, time, stats`;
    }
    
    if (command.includes('time')) {
      return `Текущее время: ${new Date().toLocaleString()}`;
    }
    
    if (command.includes('stats')) {
      const channelMembers = await this.storage.getChannelMembers(message.channel);
      return `Участников в канале: ${channelMembers.length}`;
    }

    return 'Неизвестная команда. Напишите "help" для списка команд.';
  }

  sendWebhook(bot, message) {
  }

  async deleteBot(username, owner) {
    const bot = this.bots.get(username);
    
    if (!bot || bot.owner !== owner) {
      throw new Error('Bot not found or access denied');
    }

    this.bots.delete(username);
    this.botUsers.delete(username);
    
    await this.storage.deactivateUser(username);

    return { success: true };
  }

  getUserBots(owner) {
    const userBots = [];
    
    for (const [username, bot] of this.bots) {
      if (bot.owner === owner) {
        userBots.push(bot);
      }
    }

    return userBots;
  }

  botAuthMiddleware() {
    return async (req, res, next) => {
      const auth = req.headers.authorization?.split(" ") || [];
      
      if (auth.length === 2 && auth[0] === "Bearer") {
        const user = await this.storage.validateToken(auth[1]);
        
        if (user && this.botUsers.has(user)) {
          req.user = user;
          req.isBot = true;
          req.bot = this.bots.get(user);
        }
      }

      next();
    };
  }
}
