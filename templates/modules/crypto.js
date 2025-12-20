import { createRequire } from 'module';
const require = createRequire(import.meta.url);

const rustCrypto = require('./crypto.node');

class Crypto {
  static randomBytes(size) {
    return rustCrypto.randomBytes(size);
  }

  static createHash(algorithm) {
    if (algorithm !== 'sha256' && algorithm !== 'sha1') {
      throw new Error(`Unsupported hash algorithm: ${algorithm}. Use 'sha256' or 'sha1'`);
    }
    
    let currentData = Buffer.alloc(0);
    
    return {
      update: (data) => {
        if (typeof data === 'string') {
          data = Buffer.from(data);
        }
        currentData = Buffer.concat([currentData, data]);
        return this;
      },
      digest: (encoding = 'hex') => {
        const hash = rustCrypto.createHash(currentData);
        currentData = Buffer.alloc(0);
        
        if (encoding === 'hex') {
          return hash.toString('hex');
        } else if (encoding === 'base64') {
          return hash.toString('base64');
        } else if (encoding === 'buffer') {
          return hash;
        }
        return hash;
      }
    };
  }

  static pbkdf2Sync(password, salt, iterations, keylen, digest) {
    if (digest !== 'sha256') {
      throw new Error(`Unsupported digest: ${digest}. Use 'sha256'`);
    }
    
    const key = rustCrypto.pbkdf2(
      Buffer.from(password),
      Buffer.from(salt),
      iterations
    );
    
    if (keylen && keylen < key.length) {
      return key.slice(0, keylen);
    }
    return key;
  }

  static createCipheriv(algorithm, key, iv) {
    if (algorithm !== 'aes-256-cbc') {
      throw new Error(`Unsupported cipher: ${algorithm}. Use 'aes-256-cbc'`);
    }
    
    let finalKey = Buffer.from(key);
    if (finalKey.length !== 32) {
      const derived = rustCrypto.deriveKey(finalKey, null, rustCrypto.getDefaultIterations());
      finalKey = derived.key;
    }
    
    let finalIv = iv;
    if (!finalIv) {
      finalIv = rustCrypto.randomBytes(16);
    }
    
    let dataToEncrypt = Buffer.alloc(0);
    
    return {
      iv: finalIv,
      update: (data, inputEncoding, outputEncoding) => {
        if (typeof data === 'string') {
          data = Buffer.from(data, inputEncoding || 'utf8');
        }
        dataToEncrypt = Buffer.concat([dataToEncrypt, data]);
        return Buffer.alloc(0);
      },
      final: (outputEncoding) => {
        const result = rustCrypto.encryptWithKey(
          dataToEncrypt,
          finalKey,
          finalIv
        );
        dataToEncrypt = Buffer.alloc(0);
        
        if (outputEncoding === 'hex') {
          return result.encrypted.toString('hex');
        } else if (outputEncoding === 'base64') {
          return result.encrypted.toString('base64');
        }
        return result.encrypted;
      }
    };
  }

  static createDecipheriv(algorithm, key, iv) {
    if (algorithm !== 'aes-256-cbc') {
      throw new Error(`Unsupported cipher: ${algorithm}. Use 'aes-256-cbc'`);
    }
    
    if (!iv || iv.length !== 16) {
      throw new Error('IV must be 16 bytes');
    }
    
    let finalKey = Buffer.from(key);
    if (finalKey.length !== 32) {
      const derived = rustCrypto.deriveKey(finalKey, null, rustCrypto.getDefaultIterations());
      finalKey = derived.key;
    }
    
    let dataToDecrypt = Buffer.alloc(0);
    
    return {
      update: (data, inputEncoding, outputEncoding) => {
        if (typeof data === 'string') {
          data = Buffer.from(data, inputEncoding || 'utf8');
        }
        dataToDecrypt = Buffer.concat([dataToDecrypt, data]);
        return Buffer.alloc(0);
      },
      final: (outputEncoding) => {
        const result = rustCrypto.decryptWithKey(
          dataToDecrypt,
          finalKey,
          iv
        );
        dataToDecrypt = Buffer.alloc(0);
        
        if (outputEncoding === 'utf8') {
          return result.toString('utf8');
        } else if (outputEncoding === 'hex') {
          return result.toString('hex');
        }
        return result;
      }
    };
  }

  static createCipher(algorithm, key) {
    const iv = rustCrypto.randomBytes(16);
    const cipher = this.createCipheriv('aes-256-cbc', key, iv);
    cipher.iv = iv;
    return cipher;
  }

  static createDecipher(algorithm, key, iv) {
    return this.createDecipheriv('aes-256-cbc', key, iv);
  }

  static createHmac(algorithm, key) {
    if (algorithm !== 'sha256' && algorithm !== 'sha1') {
      throw new Error(`Unsupported HMAC algorithm: ${algorithm}. Use 'sha256' or 'sha1'`);
    }
    
    let dataToHash = Buffer.alloc(0);
    
    return {
      update: (data) => {
        if (typeof data === 'string') {
          data = Buffer.from(data);
        }
        dataToHash = Buffer.concat([dataToHash, data]);
        return this;
      },
      digest: (encoding = 'hex') => {
        const hmac = rustCrypto.hmac(
          Buffer.from(key),
          dataToHash
        );
        dataToHash = Buffer.alloc(0);
        
        if (encoding === 'hex') {
          return hmac.toString('hex');
        } else if (encoding === 'base64') {
          return hmac.toString('base64');
        }
        return hmac;
      }
    };
  }

  static _deriveKey(password) {
    const result = rustCrypto.deriveKey(
      Buffer.from(password),
      null,
      rustCrypto.getDefaultIterations()
    );
    return result.key;
  }

  static base32Encode(buffer) {
    return rustCrypto.base32Encode(Buffer.from(buffer));
  }

  static base32Decode(input) {
    return rustCrypto.base32Decode(input);
  }

  static encrypt(data, password, salt = null, iterations = null) {
    const result = rustCrypto.encryptWithPassword(
      Buffer.from(data),
      Buffer.from(password),
      salt ? Buffer.from(salt) : null,
      iterations
    );
    return {
      encrypted: result.encrypted,
      iv: result.iv,
      salt: result.salt
    };
  }

  static decrypt(encrypted, password, iv, salt, iterations = null) {
    return rustCrypto.decryptWithPassword(
      Buffer.from(encrypted),
      Buffer.from(password),
      Buffer.from(iv),
      Buffer.from(salt),
      iterations
    );
  }

  static encryptString(text, password, salt = null, iterations = null) {
    const result = rustCrypto.encryptString(
      text,
      password,
      salt,
      iterations
    );
    return {
      encrypted: result.encrypted,
      iv: result.iv,
      salt: result.salt
    };
  }

  static decryptString(encrypted, password, iv, salt, iterations = null) {
    return rustCrypto.decryptString(
      encrypted,
      password,
      iv,
      salt,
      iterations
    );
  }

  static getVersion() {
    return rustCrypto.getVersion();
  }

  static getConfig() {
    return rustCrypto.getConfig();
  }
}

export { Crypto };
