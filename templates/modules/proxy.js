import { SocksProxyAgent } from 'socks-proxy-agent';
import { HttpsProxyAgent } from 'https-proxy-agent';
import tunnel from 'tunnel-ssh';
import https from 'https';
import http from 'http';
import { EventEmitter } from 'events';
import fs from 'fs';

export class ProxyManager extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = config;
    this.proxies = new Map();
    this.currentProxyIndex = 0;
    this.rotationEnabled = config.rotationEnabled || false;
    this.rotationInterval = config.rotationInterval || 30000;
    this.init();
  }

  init() {
    if (this.config.proxies && this.config.proxies.length > 0) {
      this.config.proxies.forEach((proxyConfig, index) => {
        this.addProxy(proxyConfig, index);
      });
    }

    if (this.rotationEnabled && this.proxies.size > 1) {
      this.startRotation();
    }
  }

  addProxy(proxyConfig, id = null) {
    const proxyId = id || Date.now().toString();
    const proxy = {
      id: proxyId,
      config: proxyConfig,
      type: proxyConfig.type || 'http',
      status: 'unknown',
      lastUsed: 0,
      successCount: 0,
      failureCount: 0,
      agent: null
    };

    this.createProxyAgent(proxy);
    this.proxies.set(proxyId, proxy);

    this.emit('proxyAdded', proxy);
    return proxyId;
  }

  async createProxyAgent(proxy) {
    try {
      let agent = null;
      const proxyUrl = this.buildProxyUrl(proxy.config);

      switch (proxy.type) {
        case 'socks5':
        case 'socks4':
          agent = new SocksProxyAgent(proxyUrl);
          break;

        case 'http':
        case 'https':
          agent = new HttpsProxyAgent(proxyUrl);
          break;

        case 'ssh':
          agent = await this.createSSHTunnel(proxy.config);
          break;

        default:
          throw new Error(`Unsupported proxy type: ${proxy.type}`);
      }

      if (agent) {
        proxy.agent = agent;
        proxy.status = 'active';
      }

    } catch (error) {
      proxy.status = 'error';
      proxy.error = error.message;
      this.emit('proxyError', proxy, error);
    }
  }

  buildProxyUrl(config) {
    const { type, host, port, username, password } = config;
    
    let auth = '';
    if (username && password) {
      auth = `${encodeURIComponent(username)}:${encodeURIComponent(password)}@`;
    }

    switch (type) {
      case 'socks5':
        return `socks5://${auth}${host}:${port}`;
      case 'socks4':
        return `socks4://${auth}${host}:${port}`;
      case 'http':
      case 'https':
        return `${type}://${auth}${host}:${port}`;
      default:
        throw new Error(`Cannot build URL for proxy type: ${type}`);
    }
  }

  createSSHTunnel(sshConfig) {
    return new Promise((resolve, reject) => {
      const tunnelConfig = {
        username: sshConfig.username,
        host: sshConfig.host,
        port: sshConfig.port || 22,
        password: sshConfig.password,
        dstHost: sshConfig.dstHost || '127.0.0.1',
        dstPort: sshConfig.dstPort || 1080,
        localHost: '127.0.0.1',
        localPort: 0
      };

      if (sshConfig.privateKey) {
        if (fs.existsSync(sshConfig.privateKey)) {
          tunnelConfig.privateKey = fs.readFileSync(sshConfig.privateKey);
        } else {
          tunnelConfig.privateKey = Buffer.from(sshConfig.privateKey);
        }
      }

      tunnel(tunnelConfig, (error, server) => {
        if (error) {
          reject(error);
          return;
        }

        const localPort = server.address().port;
        const agent = new SocksProxyAgent(`socks5://127.0.0.1:${localPort}`);
        
        agent.tunnelServer = server;
        
        resolve(agent);
      });
    });
  }

  getNextProxy() {
    if (this.proxies.size === 0) {
      return null;
    }

    const proxyArray = Array.from(this.proxies.values())
      .filter(proxy => proxy.status === 'active' && proxy.agent);
    
    if (proxyArray.length === 0) {
      return null;
    }

    if (this.rotationEnabled) {
      this.currentProxyIndex = (this.currentProxyIndex + 1) % proxyArray.length;
      return proxyArray[this.currentProxyIndex];
    } else {
      return proxyArray.reduce((leastUsed, proxy) => 
        proxy.lastUsed < leastUsed.lastUsed ? proxy : leastUsed
      );
    }
  }

  getProxyAgent(proxyId = null) {
    let proxy;
    
    if (proxyId && this.proxies.has(proxyId)) {
      proxy = this.proxies.get(proxyId);
    } else {
      proxy = this.getNextProxy();
    }

    if (!proxy || !proxy.agent) {
      return null;
    }

    proxy.lastUsed = Date.now();
    return proxy.agent;
  }

  async makeRequest(options, data = null) {
    const proxy = this.getNextProxy();
    if (!proxy) {
      throw new Error('No available proxies');
    }

    try {
      const agent = proxy.agent;
      const requestOptions = {
        ...options,
        agent
      };

      const response = await this.executeRequest(requestOptions, data);
      proxy.successCount++;
      this.emit('requestSuccess', proxy, response);
      
      return response;

    } catch (error) {
      proxy.failureCount++;
      proxy.status = 'error';
      proxy.lastError = error.message;
      this.emit('requestFailed', proxy, error);
      
      if (this.proxies.size > 1) {
        return this.makeRequest(options, data);
      }
      
      throw error;
    }
  }

  executeRequest(options, data) {
    return new Promise((resolve, reject) => {
      const protocol = options.protocol === 'https:' ? https : http;
      
      const req = protocol.request(options, (res) => {
        let responseData = '';
        
        res.on('data', (chunk) => {
          responseData += chunk;
        });
        
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            data: responseData
          });
        });
      });

      req.on('error', (error) => {
        reject(error);
      });

      req.setTimeout(options.timeout || 30000, () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      if (data) {
        req.write(data);
      }

      req.end();
    });
  }

  startRotation() {
    this.rotationIntervalId = setInterval(() => {
      this.currentProxyIndex = (this.currentProxyIndex + 1) % this.proxies.size;
      this.emit('proxyRotated', this.getCurrentProxy());
    }, this.rotationInterval);
  }

  stopRotation() {
    if (this.rotationIntervalId) {
      clearInterval(this.rotationIntervalId);
      this.rotationIntervalId = null;
    }
  }

  getCurrentProxy() {
    const proxyArray = Array.from(this.proxies.values());
    return proxyArray[this.currentProxyIndex];
  }

  getProxyStats() {
    const stats = {
      total: this.proxies.size,
      active: 0,
      errors: 0,
      proxies: []
    };

    for (const proxy of this.proxies.values()) {
      if (proxy.status === 'active') stats.active++;
      if (proxy.status === 'error') stats.errors++;
      
      stats.proxies.push({
        id: proxy.id,
        type: proxy.type,
        status: proxy.status,
        successCount: proxy.successCount,
        failureCount: proxy.failureCount,
        lastUsed: proxy.lastUsed,
        lastError: proxy.lastError
      });
    }

    return stats;
  }

  removeProxy(proxyId) {
    const proxy = this.proxies.get(proxyId);
    if (proxy) {
      if (proxy.agent && proxy.agent.tunnelServer) {
        proxy.agent.tunnelServer.close();
      }
      
      this.proxies.delete(proxyId);
      this.emit('proxyRemoved', proxyId);
      return true;
    }
    return false;
  }

  testProxy(proxyId) {
    const proxy = this.proxies.get(proxyId);
    if (!proxy) {
      return Promise.reject(new Error('Proxy not found'));
    }

    const testOptions = {
      hostname: 'httpbin.org',
      port: 443,
      path: '/ip',
      method: 'GET',
      protocol: 'https:'
    };

    return this.makeRequest(testOptions)
      .then(response => {
        proxy.status = 'active';
        return JSON.parse(response.data);
      })
      .catch(error => {
        proxy.status = 'error';
        throw error;
      });
  }

  async testAllProxies() {
    const results = [];
    
    for (const [proxyId, proxy] of this.proxies.entries()) {
      try {
        const result = await this.testProxy(proxyId);
        results.push({
          proxyId,
          status: 'success',
          data: result
        });
      } catch (error) {
        results.push({
          proxyId,
          status: 'error',
          error: error.message
        });
      }
    }

    return results;
  }

  cleanup() {
    this.stopRotation();
    
    for (const proxy of this.proxies.values()) {
      if (proxy.agent && proxy.agent.tunnelServer) {
        proxy.agent.tunnelServer.close();
      }
    }
    
    this.proxies.clear();
  }
}

export class ProxyPresets {
  static torProxy() {
    return new ProxyManager({
      proxies: [
        {
          type: 'socks5',
          host: '127.0.0.1',
          port: 9050
        }
      ],
      rotationEnabled: false
    });
  }

  static multiHTTP(proxies) {
    return new ProxyManager({
      proxies: proxies.map(proxy => ({ type: 'http', ...proxy })),
      rotationEnabled: true,
      rotationInterval: 60000
    });
  }

  static sshTunnel(sshConfig) {
    return new ProxyManager({
      proxies: [{
        type: 'ssh',
        ...sshConfig
      }],
      rotationEnabled: false
    });
  }
}

export function proxyMiddleware(proxyManager) {
  return (req, res, next) => {
    req.proxyManager = proxyManager;
    next();
  };
}

export class ProxyClient {
  constructor(proxyManager) {
    this.proxyManager = proxyManager;
  }

  async get(url, options = {}) {
    const urlObj = new URL(url);
    
    const requestOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      protocol: urlObj.protocol,
      headers: options.headers || {}
    };

    return this.proxyManager.makeRequest(requestOptions);
  }

  async post(url, data, options = {}) {
    const urlObj = new URL(url);
    const postData = typeof data === 'string' ? data : JSON.stringify(data);
    
    const requestOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      protocol: urlObj.protocol,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        ...options.headers
      }
    };

    return this.proxyManager.makeRequest(requestOptions, postData);
  }
}
