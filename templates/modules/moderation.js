export class ModerationSystem {
  constructor(storage) {
    this.storage = storage;
    this.warnings = new Map();
  }

  async banUser(username, durationMs, reason, moderator) {
    const banInfo = {
      username,
      reason,
      moderator,
      bannedAt: Date.now(),
      expires: Date.now() + durationMs,
      active: true
    };

    await this.storage.saveBan(banInfo);

    await this.kickUserFromAllChannels(username);

    return banInfo;
  }

  async unbanUser(username, moderator) {
    await this.storage.removeBan(username);
    
    return { success: true, message: `User ${username} unbanned` };
  }

  async warnUser(username, reason, moderator) {
    const warning = {
      username,
      reason,
      moderator,
      timestamp: Date.now(),
      acknowledged: false
    };

    const warnings = this.warnings.get(username) || [];
    warnings.push(warning);
    this.warnings.set(username, warnings);

    if (warnings.length >= 3) {
      return await this.banUser(username, 24 * 60 * 60 * 1000, 'auto_ban_3_warnings', 'system');
    }

    return warning;
  }

  async kickUser(channel, username, moderator) {
    const result = await this.storage.leaveChannel(channel, username);
    
    if (result) {
      this.notifyChannel(channel, {
        type: 'user_kicked',
        username,
        moderator,
        channel,
        timestamp: Date.now()
      });
    }

    return result;
  }

  async kickUserFromAllChannels(username) {
    const channels = await this.storage.getChannels(username);
    
    for (const channel of channels) {
      await this.storage.leaveChannel(channel.id, username);
    }

    return channels.length;
  }

  async checkBan(username) {
    const ban = await this.storage.getBan(username);
    
    if (ban && ban.active && ban.expires > Date.now()) {
      return {
        banned: true,
        reason: ban.reason,
        expires: ban.expires,
        moderator: ban.moderator
      };
    }

    return { banned: false };
  }

  getUserWarnings(username) {
    return this.warnings.get(username) || [];
  }

  banCheckMiddleware() {
    return async (req, res, next) => {
      if (!req.user) return next();

      const banCheck = await this.checkBan(req.user);
      if (banCheck.banned) {
        return res.status(403).json({
          error: 'banned',
          reason: banCheck.reason,
          expires: banCheck.expires,
          moderator: banCheck.moderator
        });
      }

      next();
    };
  }

  notifyChannel(channel, data) {
  }
}
