import { createRequire } from 'module';
const require = createRequire(import.meta.url);

// Загружаем Rust TOTP модуль напрямую
const rustTotp = require('./totp.node');
import { Crypto } from './crypto.js';

class TOTP {
  static generateSecret(options = {}) {
    const length = options.length || 32;
    
    // Используем Rust для генерации секрета
    const secret = rustTotp.generateTotpSecret(length);
    
    // Конвертируем base32 в Buffer для ASCII и HEX представлений
    let secretBuffer;
    try {
      secretBuffer = Crypto.base32Decode(secret);
    } catch (error) {
      // Fallback: если есть ошибка, создаем пустой buffer
      secretBuffer = Buffer.alloc(0);
    }
    
    return {
      base32: secret,
      ascii: secretBuffer.length > 0 ? secretBuffer.toString('ascii') : '',
      hex: secretBuffer.length > 0 ? secretBuffer.toString('hex') : '',
      otpauth_url: `otpauth://totp/${encodeURIComponent(options.name || 'App')}?secret=${secret}&issuer=${encodeURIComponent(options.issuer || 'App')}`
    };
  }

  static verify({ secret, token, window = 1, encoding = 'base32' }) {
    let finalSecret = secret;
    
    // Конвертируем секрет в base32 если нужно
    if (encoding !== 'base32') {
      if (encoding === 'hex') {
        // HEX -> Buffer -> base32
        const buffer = Buffer.from(secret, 'hex');
        finalSecret = Crypto.base32Encode(buffer);
      } else if (encoding === 'ascii') {
        // ASCII -> Buffer -> base32
        const buffer = Buffer.from(secret, 'ascii');
        finalSecret = Crypto.base32Encode(buffer);
      } else {
        throw new Error(`Unsupported encoding: ${encoding}. Use 'base32', 'hex', or 'ascii'`);
      }
    }
    
    // Используем Rust для верификации
    return rustTotp.verifyTotp(
      finalSecret,
      parseInt(token),
      30,     // step
      0,      // t0
      window  // window
    );
  }

  static generateTOTP(secret, time, encoding = 'base32') {
    let finalSecret = secret;
    
    if (encoding !== 'base32') {
      if (encoding === 'hex') {
        const buffer = Buffer.from(secret, 'hex');
        finalSecret = Crypto.base32Encode(buffer);
      } else if (encoding === 'ascii') {
        const buffer = Buffer.from(secret, 'ascii');
        finalSecret = Crypto.base32Encode(buffer);
      } else {
        throw new Error(`Unsupported encoding: ${encoding}`);
      }
    }
    
    // Используем Rust для генерации TOTP
    const code = rustTotp.totpRaw(
      finalSecret,
      30,  // step
      0,   // t0
      time // unix time
    );
    
    return code.toString().padStart(6, '0');
  }

  static generateTOTPNow(secret, encoding = 'base32') {
    const time = Math.floor(Date.now() / 1000);
    return this.generateTOTP(secret, time, encoding);
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

  // Методы для работы с QR кодами - используем camelCase
  static generateQRCode(secret, accountName, issuer, options = {}) {
    const config = {
      accountName: accountName,  // camelCase - NAPI преобразует в account_name
      issuer: issuer,
      darkColor: options.darkColor || '#000000',
      lightColor: options.lightColor || '#ffffff',
      minDimension: options.minDimension || 250,
      version: options.version || 5,
      ecLevel: options.ecLevel || 'M'
    };
    
    return rustTotp.totpQrSvg(secret, config);
  }

  static generateSetupPackage(length = 32, accountName, issuer, options = {}) {
    const secret = rustTotp.generateTotpSecret(length);
    
    // Генерируем QR код
    const qrCode = this.generateQRCode(secret, accountName, issuer, options);
    
    // Возвращаем объект
    return {
      secret: secret,
      qrCode: qrCode,
      accountName: accountName,
      issuer: issuer,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      otpauth_url: `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`
    };
  }

  // Используем новую JS-совместимую функцию если она есть
  static generateJsSetupPackage(length = 32, accountName, issuer, options = {}) {
    if (rustTotp.generateTotpSetupJs) {
      const result = rustTotp.generateTotpSetupJs(length, accountName, issuer);
      return {
        secret: result.secret,
        qrCode: result.qr_code,  // snake_case от Rust
        accountName: result.accountName,
        issuer: result.issuer,
        algorithm: result.algorithm,
        digits: result.digits,
        period: result.period
      };
    }
    
    // Fallback на обычную версию
    return this.generateSetupPackage(length, accountName, issuer, options);
  }

  static async verifyWithWindow(secret, token, window = 2, encoding = 'base32') {
    // Проверяем несколько временных окон
    for (let i = -window; i <= window; i++) {
      const time = Math.floor(Date.now() / 1000) + (i * 30);
      const expectedToken = this.generateTOTP(secret, time, encoding);
      if (this.constantTimeCompare(expectedToken, token.toString())) {
        return true;
      }
    }
    return false;
  }

  // Метод для генерации секрета с проверкой
  static generateValidatedSecret(length = 32, options = {}) {
    let secret;
    let attempts = 0;
    const maxAttempts = 10;
    
    do {
      secret = this.generateSecret({ ...options, length });
      attempts++;
    } while (!this.validateSecret(secret.base32) && attempts < maxAttempts);
    
    if (attempts === maxAttempts) {
      throw new Error('Failed to generate valid secret after multiple attempts');
    }
    
    return secret;
  }

  // Альтернативный метод верификации для совместимости
  static verifyToken(secret, token, options = {}) {
    const { window = 1, encoding = 'base32' } = options;
    return this.verify({ secret, token, window, encoding });
  }
}

export { TOTP };
