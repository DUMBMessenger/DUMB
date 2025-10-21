export class RateLimiter {
  constructor(windowMs, max) {
    this.windowMs = windowMs;
    this.max = max;
    this.hits = new Map();
  }

  check(ip) {
    const now = Date.now();
    const windowStart = now - this.windowMs;
    
    let ipHits = this.hits.get(ip) || [];
    
    ipHits = ipHits.filter(timestamp => timestamp > windowStart);
    
    if (ipHits.length >= this.max) {
      return false;
    }
    
    ipHits.push(now);
    this.hits.set(ip, ipHits);
    
    if (now % 60000 < 100) {
      this.cleanup();
    }
    
    return true;
  }

  cleanup() {
    const now = Date.now();
    const windowStart = now - this.windowMs;
    
    for (const [ip, hits] of this.hits.entries()) {
      const freshHits = hits.filter(timestamp => timestamp > windowStart);
      if (freshHits.length === 0) {
        this.hits.delete(ip);
      } else {
        this.hits.set(ip, freshHits);
      }
    }
  }

  middleware() {
    return (req, res, next) => {
      const ip = req.ip || 'unknown';
      
      if (!this.check(ip)) {
        Logger.warn('Rate limit exceeded', { ip });
        return res.status(429).json({ error: 'rate limit' });
      }
      
      next();
    };
  }
}
