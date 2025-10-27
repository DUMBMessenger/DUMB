import redis from 'redis';

export class RedisService {
  constructor(config) {
    this.config = config;
    this.client = null;
    this.connected = false;
    this.memoryCache = new Map();
  }

  async connect() {
    if (!this.config.enabled) {
      return;
    }

    try {
      this.client = redis.createClient({
        url: this.config.url,
        password: this.config.password,
        socket: {
          connectTimeout: 10000,
          reconnectStrategy: (retries) => Math.min(retries * 100, 3000)
        }
      });

      this.client.on('error', (err) => {
        this.connected = false;
      });

      this.client.on('connect', () => {
        this.connected = true;
      });

      this.client.on('disconnect', () => {
        this.connected = false;
      });

      await this.client.connect();
    } catch (error) {
      this.connected = false;
    }
  }

  async set(key, value, ttlSeconds = null) {
    if (!this.config.enabled || !this.connected) {
      this.memoryCache.set(key, value);
      if (ttlSeconds) {
        setTimeout(() => this.memoryCache.delete(key), ttlSeconds * 1000);
      }
      return true;
    }

    try {
      if (ttlSeconds) {
        await this.client.setEx(key, ttlSeconds, JSON.stringify(value));
      } else {
        await this.client.set(key, JSON.stringify(value));
      }
      return true;
    } catch (error) {
      this.memoryCache.set(key, value);
      return false;
    }
  }

  async get(key) {
    if (!this.config.enabled || !this.connected) {
      return this.memoryCache.get(key) || null;
    }

    try {
      const value = await this.client.get(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      return this.memoryCache.get(key) || null;
    }
  }

  async del(key) {
    if (!this.config.enabled || !this.connected) {
      return this.memoryCache.delete(key);
    }

    try {
      await this.client.del(key);
      this.memoryCache.delete(key);
      return true;
    } catch (error) {
      return this.memoryCache.delete(key);
    }
  }

  async exists(key) {
    if (!this.config.enabled || !this.connected) {
      return this.memoryCache.has(key);
    }

    try {
      return await this.client.exists(key);
    } catch (error) {
      return this.memoryCache.has(key);
    }
  }

  async cache(key, ttlSeconds, fetchFunction) {
    const cached = await this.get(key);
    if (cached !== null) {
      return cached;
    }

    const freshData = await fetchFunction();
    await this.set(key, freshData, ttlSeconds);
    return freshData;
  }

  async setSession(sessionId, data, ttlSeconds = 3600) {
    return await this.set(`session:${sessionId}`, data, ttlSeconds);
  }

  async getSession(sessionId) {
    return await this.get(`session:${sessionId}`);
  }

  async deleteSession(sessionId) {
    return await this.del(`session:${sessionId}`);
  }

  async cacheMessages(channel, messages, ttlSeconds = 300) {
    return await this.set(`messages:${channel}`, messages, ttlSeconds);
  }

  async getCachedMessages(channel) {
    return await this.get(`messages:${channel}`);
  }

  async invalidateChannel(channel) {
    await this.del(`messages:${channel}`);
  }

  async cacheUserChannels(username, channels, ttlSeconds = 600) {
    return await this.set(`user_channels:${username}`, channels, ttlSeconds);
  }

  async getCachedUserChannels(username) {
    return await this.get(`user_channels:${username}`);
  }

  async invalidateUserChannels(username) {
    await this.del(`user_channels:${username}`);
  }

  async getStats() {
    if (!this.config.enabled || !this.connected) {
      return {
        enabled: false,
        connected: false,
        memoryKeys: this.memoryCache.size
      };
    }

    try {
      const info = await this.client.info();
      const keys = await this.client.dbSize();
      return {
        enabled: true,
        connected: true,
        keys: keys,
        memoryKeys: this.memoryCache.size,
        info: info.substring(0, 200) + '...'
      };
    } catch (error) {
      return {
        enabled: true,
        connected: false,
        error: error.message,
        memoryKeys: this.memoryCache.size
      };
    }
  }

  async cleanup() {
    if (!this.config.enabled || !this.connected) {
      const now = Date.now();
      for (const [key, value] of this.memoryCache.entries()) {
        if (value._expire && value._expire < now) {
          this.memoryCache.delete(key);
        }
      }
      return;
    }
  }
}
