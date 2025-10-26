export class Firewall {
  constructor(config) {
    this.config = config;
    this.blockedIPs = new Map();
    this.suspiciousIPs = new Map();
    this.requestCounts = new Map();
    this.autoBlockEnabled = config.autoBlock || true;
  }

  async checkIP(ip, userAgent = '') {
    if (this.blockedIPs.has(ip)) {
      const blockInfo = this.blockedIPs.get(ip);
      if (blockInfo.expires > Date.now()) {
        return { allowed: false, reason: 'IP blocked', expires: blockInfo.expires };
      } else {
        this.blockedIPs.delete(ip);
      }
    }

    if (this.suspiciousIPs.has(ip)) {
      const suspicious = this.suspiciousIPs.get(ip);
      if (suspicious.score > this.config.suspiciousThreshold) {
        return { allowed: false, reason: 'Suspicious activity' };
      }
    }

    if (this.isSuspiciousUserAgent(userAgent)) {
      this.markSuspicious(ip, 'suspicious_user_agent');
      return { allowed: false, reason: 'Suspicious user agent' };
    }

    return { allowed: true };
  }

  isSuspiciousUserAgent(userAgent) {
    const suspiciousPatterns = [
      /bot|crawl|spider|scraper/i,
      /curl|wget|libwww/i,
      /nikto|sqlmap|nmap/i,
      /masscan|zmap|metasploit/i
    ];

    return suspiciousPatterns.some(pattern => pattern.test(userAgent));
  }

  markSuspicious(ip, reason, score = 10) {
    const existing = this.suspiciousIPs.get(ip) || { score: 0, reasons: [] };
    existing.score += score;
    existing.reasons.push({ reason, timestamp: Date.now() });
    this.suspiciousIPs.set(ip, existing);

    if (this.autoBlockEnabled && existing.score >= this.config.autoBlockThreshold) {
      this.blockIP(ip, 24 * 60 * 60 * 1000, 'automatic_block');
    }

    this.cleanupSuspicious();
  }

  blockIP(ip, durationMs = 3600000, reason = 'manual') {
    this.blockedIPs.set(ip, {
      reason,
      blockedAt: Date.now(),
      expires: Date.now() + durationMs
    });
  }

  unblockIP(ip) {
    this.blockedIPs.delete(ip);
    this.suspiciousIPs.delete(ip);
  }

  cleanupSuspicious() {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000;

    for (const [ip, data] of this.suspiciousIPs.entries()) {
      data.reasons = data.reasons.filter(r => now - r.timestamp < maxAge);
      if (data.reasons.length === 0) {
        this.suspiciousIPs.delete(ip);
      }
    }

    for (const [ip, block] of this.blockedIPs.entries()) {
      if (block.expires < now) {
        this.blockedIPs.delete(ip);
      }
    }
  }

  middleware() {
    return async (req, res, next) => {
      const ip = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent') || '';

      const check = await this.checkIP(ip, userAgent);
      if (!check.allowed) {
        return res.status(403).json({
          error: 'access_denied',
          reason: check.reason,
          expires: check.expires
        });
      }

      this.logRequest(ip, req.path, userAgent);
      next();
    };
  }

  logRequest(ip, path, userAgent) {
  }

  getStats() {
    return {
      blockedIPs: this.blockedIPs.size,
      suspiciousIPs: this.suspiciousIPs.size,
      autoBlockEnabled: this.autoBlockEnabled
    };
  }
}
