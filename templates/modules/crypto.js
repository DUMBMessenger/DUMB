import { randomBytes, createHash, pbkdf2Sync, createCipheriv, createDecipheriv } from 'crypto';

export class Crypto {
  static randomBytes(size) {
    return randomBytes(size);
  }

  static createHash(algorithm) {
    return createHash(algorithm);
  }

  static pbkdf2Sync(password, salt, iterations, keylen, digest) {
    return pbkdf2Sync(password, salt, iterations, keylen, digest);
  }

  static createCipher(algorithm, key) {
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-cbc', this._deriveKey(key), iv);
    cipher.iv = iv;
    return cipher;
  }

  static createDecipher(algorithm, key, iv) {
    return createDecipheriv('aes-256-cbc', this._deriveKey(key), iv);
  }

  static createHmac(algorithm, key) {
    return {
      update: (data) => {
        this._hmacData = data;
        return this;
      },
      digest: (encoding = 'hex') => {
        const hmac = createHash(algorithm);
        hmac.update(key);
        hmac.update(this._hmacData);
        return hmac.digest(encoding);
      }
    };
  }

  static _deriveKey(password) {
    return pbkdf2Sync(password, 'salt', 100000, 32, 'sha256');
  }

  static base32Encode(buffer) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    let output = '';

    for (let i = 0; i < buffer.length; i++) {
      bits += buffer[i].toString(2).padStart(8, '0');
    }

    while (bits.length % 5 !== 0) {
      bits += '0';
    }

    for (let i = 0; i < bits.length; i += 5) {
      const chunk = bits.substr(i, 5);
      output += alphabet[parseInt(chunk, 2)];
    }

    const padding = 8 - (output.length % 8);
    if (padding !== 8) {
      output += '='.repeat(padding);
    }

    return output;
  }

  static base32Decode(input) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    input = input.toUpperCase().replace(/=+$/, '');
    
    let bits = '';
    for (let i = 0; i < input.length; i++) {
      const index = alphabet.indexOf(input[i]);
      if (index === -1) continue;
      bits += index.toString(2).padStart(5, '0');
    }

    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.substr(i, 8), 2));
    }

    return Buffer.from(bytes);
  }
}
