import { Crypto } from './crypto.js';

export class TOTP {
  static generateSecret(options = {}) {
    const length = options.length || 32;
    const bytes = Crypto.randomBytes(length);
    const base32Secret = Crypto.base32Encode(bytes);
    
    return {
      base32: base32Secret,
      ascii: bytes.toString('ascii'),
      hex: bytes.toString('hex'),
      otpauth_url: `otpauth://totp/${encodeURIComponent(options.name || 'App')}?secret=${base32Secret}&issuer=${encodeURIComponent(options.issuer || 'App')}`
    };
  }

  static verify({ secret, token, window = 1, encoding = 'base32' }) {
    const timeStep = 30;
    const currentTime = Math.floor(Date.now() / 1000);
    
    for (let i = -window; i <= window; i++) {
      const time = currentTime + (i * timeStep);
      const expectedToken = this.generateTOTP(secret, time, encoding);
      if (this.constantTimeCompare(expectedToken, token.toString())) {
        return true;
      }
    }
    
    return false;
  }

  static generateTOTP(secret, time, encoding = 'base32') {
    let key;
    if (encoding === 'base32') {
      key = Crypto.base32Decode(secret);
    } else {
      key = Buffer.from(secret, encoding);
    }

    const timeBuffer = Buffer.alloc(8);
    let timeCounter = Math.floor(time / 30);
    
    for (let i = 7; i >= 0; i--) {
      timeBuffer[i] = timeCounter & 0xff;
      timeCounter >>>= 8;
    }

    const hmac = Crypto.createHmac('sha1', key);
    const hash = hmac.update(timeBuffer).digest('hex');
    const hashBuffer = Buffer.from(hash, 'hex');

    const offset = hashBuffer[hashBuffer.length - 1] & 0xf;
    const binary = 
      ((hashBuffer[offset] & 0x7f) << 24) |
      ((hashBuffer[offset + 1] & 0xff) << 16) |
      ((hashBuffer[offset + 2] & 0xff) << 8) |
      (hashBuffer[offset + 3] & 0xff);

    const otp = binary % 1000000;
    return otp.toString().padStart(6, '0');
  }

  static constantTimeCompare(a, b) {
    if (a.length !== b.length) {
      return false;
    }
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }

  static validateSecret(secret) {
    const base32Regex = /^[A-Z2-7]+=*$/i;
    return base32Regex.test(secret) && secret.length >= 16;
  }
}
