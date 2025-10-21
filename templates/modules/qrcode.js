export class QRCode {
  static async toDataURL(text, options = {}) {
    const {
      width = 256,
      height = 256,
      margin = 4,
      colorDark = '#000000',
      colorLight = '#ffffff',
      correctLevel = 'M'
    } = options;

    const qrMatrix = this.generateQRMatrix(text, correctLevel);
    const scale = Math.min(
      Math.floor((width - margin * 2) / qrMatrix.length),
      Math.floor((height - margin * 2) / qrMatrix.length)
    );

    const actualSize = qrMatrix.length * scale + margin * 2;
    
    let svg = `<svg width="${actualSize}" height="${actualSize}" xmlns="http://www.w3.org/2000/svg">`;
    svg += `<rect width="100%" height="100%" fill="${colorLight}"/>`;
    
    for (let y = 0; y < qrMatrix.length; y++) {
      for (let x = 0; x < qrMatrix[y].length; x++) {
        if (qrMatrix[y][x]) {
          svg += `<rect x="${x * scale + margin}" y="${y * scale + margin}" width="${scale}" height="${scale}" fill="${colorDark}"/>`;
        }
      }
    }
    
    svg += '</svg>';
    return `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`;
  }

  static generateQRMatrix(data, correctLevel = 'M') {
    const encoding = this.chooseEncoding(data);
    const version = this.determineVersion(data, encoding, correctLevel);
    const matrix = this.createBaseMatrix(version);
    
    const encodedData = this.encodeData(data, encoding, version, correctLevel);
    this.placeData(matrix, encodedData, version);
    
    this.applyMask(matrix, this.chooseBestMask(matrix));
    this.addFormatInfo(matrix, correctLevel);
    
    return matrix;
  }

  static chooseEncoding(data) {
    if (/^[0-9]*$/.test(data)) return 'numeric';
    if (/^[0-9A-Z $%*+\-./:]*$/.test(data)) return 'alphanumeric';
    return 'byte';
  }

  static determineVersion(data, encoding, correctLevel) {
    const capacity = {
      'L': { 'numeric': 41, 'alphanumeric': 25, 'byte': 17 },
      'M': { 'numeric': 34, 'alphanumeric': 20, 'byte': 14 },
      'Q': { 'numeric': 27, 'alphanumeric': 16, 'byte': 11 },
      'H': { 'numeric': 17, 'alphanumeric': 10, 'byte': 7 }
    };

    const maxLength = capacity[correctLevel][encoding];
    return data.length <= maxLength ? 1 : Math.ceil(data.length / maxLength);
  }

  static createBaseMatrix(version) {
    const size = 21 + (version - 1) * 4;
    const matrix = Array(size).fill().map(() => Array(size).fill(false));
    
    this.addFinderPattern(matrix, 0, 0);
    this.addFinderPattern(matrix, size - 7, 0);
    this.addFinderPattern(matrix, 0, size - 7);
    
    this.addAlignmentPatterns(matrix, version);
    
    for (let i = 8; i < size - 8; i++) {
      matrix[6][i] = i % 2 === 0;
      matrix[i][6] = i % 2 === 0;
    }
    
    matrix[size - 8][8] = true;
    
    return matrix;
  }

  static addFinderPattern(matrix, x, y) {
    const pattern = [
      [true, true, true, true, true, true, true],
      [true, false, false, false, false, false, true],
      [true, false, true, true, true, false, true],
      [true, false, true, true, true, false, true],
      [true, false, true, true, true, false, true],
      [true, false, false, false, false, false, true],
      [true, true, true, true, true, true, true]
    ];
    
    for (let i = 0; i < 7; i++) {
      for (let j = 0; j < 7; j++) {
        matrix[y + i][x + j] = pattern[i][j];
      }
    }
  }

  static addAlignmentPatterns(matrix, version) {
    if (version < 2) return;
    
    const positions = this.getAlignmentPatternPositions(version);
    for (const x of positions) {
      for (const y of positions) {
        if ((x < 9 && y < 9) || (x < 9 && y > matrix.length - 10) || (x > matrix.length - 10 && y < 9)) {
          continue;
        }
        this.addAlignmentPattern(matrix, x - 2, y - 2);
      }
    }
  }

  static getAlignmentPatternPositions(version) {
    const patterns = {
      2: [6, 18],
      3: [6, 22],
      4: [6, 26],
    };
    return patterns[version] || [6];
  }

  static addAlignmentPattern(matrix, x, y) {
    for (let i = 0; i < 5; i++) {
      for (let j = 0; j < 5; j++) {
        const isBorder = i === 0 || i === 4 || j === 0 || j === 4;
        const isCenter = i === 2 && j === 2;
        matrix[y + i][x + j] = isBorder || isCenter;
      }
    }
  }

  static encodeData(data, encoding, version, correctLevel) {
    let bits = '';
    
    switch (encoding) {
      case 'numeric': bits += '0001'; break;
      case 'alphanumeric': bits += '0010'; break;
      case 'byte': bits += '0100'; break;
    }
    
    const countBits = this.getCharacterCountBits(version, encoding);
    bits += data.length.toString(2).padStart(countBits, '0');
    
    if (encoding === 'byte') {
      for (let i = 0; i < data.length; i++) {
        bits += data.charCodeAt(i).toString(2).padStart(8, '0');
      }
    } else {
      for (let i = 0; i < data.length; i++) {
        bits += data.charCodeAt(i).toString(2).padStart(8, '0');
      }
    }
    
    bits += '0000';
    
    while (bits.length % 8 !== 0) {
      bits += '0';
    }
    
    const paddingBytes = ['11101100', '00010001'];
    let padIndex = 0;
    while (bits.length < this.getDataCapacity(version, correctLevel) * 8) {
      bits += paddingBytes[padIndex];
      padIndex = (padIndex + 1) % 2;
    }
    
    return bits;
  }

  static getCharacterCountBits(version, encoding) {
    if (version < 10) {
      return encoding === 'numeric' ? 10 : encoding === 'alphanumeric' ? 9 : 8;
    } else if (version < 27) {
      return encoding === 'numeric' ? 12 : encoding === 'alphanumeric' ? 11 : 16;
    } else {
      return encoding === 'numeric' ? 14 : encoding === 'alphanumeric' ? 13 : 16;
    }
  }

  static getDataCapacity(version, correctLevel) {
    const capacities = {
      'L': [19, 34, 55, 80, 108, 136, 156, 194, 232],
      'M': [16, 28, 44, 64, 86, 108, 124, 154, 182],
      'Q': [13, 22, 34, 48, 62, 76, 88, 110, 132],
      'H': [9, 16, 26, 36, 46, 60, 66, 86, 100]
    };
    return capacities[correctLevel][version - 1] || 19;
  }

  static placeData(matrix, dataBits, version) {
    const size = matrix.length;
    let bitIndex = 0;
    
    for (let right = size - 1; right >= 0; right -= 2) {
      if (right === 6) right = 5;
      
      for (let vert = 0; vert < size; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const upward = Math.floor((right + 1) / 2) % 2 === 0;
          const y = upward ? size - 1 - vert : vert;
          
          if (!matrix[y][x] && bitIndex < dataBits.length) {
            matrix[y][x] = dataBits[bitIndex] === '1';
            bitIndex++;
          }
        }
      }
    }
  }

  static applyMask(matrix, maskPattern) {
    const size = matrix.length;
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (this.isDataCell(matrix, x, y)) {
          let invert = false;
          switch (maskPattern) {
            case 0: invert = (x + y) % 2 === 0; break;
            case 1: invert = y % 2 === 0; break;
            case 2: invert = x % 3 === 0; break;
            case 3: invert = (x + y) % 3 === 0; break;
            case 4: invert = (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0; break;
            case 5: invert = ((x * y) % 2) + ((x * y) % 3) === 0; break;
            case 6: invert = (((x * y) % 2) + ((x * y) % 3)) % 2 === 0; break;
            case 7: invert = (((x + y) % 2) + ((x * y) % 3)) % 2 === 0; break;
          }
          if (invert) matrix[y][x] = !matrix[y][x];
        }
      }
    }
  }

  static chooseBestMask(matrix) {
    return 0;
  }

  static addFormatInfo(matrix, correctLevel) {
    const formatInfo = {
      'L': [1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0],
      'M': [1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0],
      'Q': [1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1],
      'H': [1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0]
    };
    
    const infoBits = formatInfo[correctLevel];
    const size = matrix.length;
    
    for (let i = 0; i < 15; i++) {
      matrix[8][i < 6 ? i : i + 1] = !!infoBits[i];
      matrix[i < 8 ? i : i + 1][8] = !!infoBits[i];
      
      matrix[8][size - 1 - i] = !!infoBits[14 - i];
      matrix[size - 1 - i][8] = !!infoBits[14 - i];
    }
  }

  static isDataCell(matrix, x, y) {
    const size = matrix.length;
    return !(
      (x < 9 && y < 9) ||
      (x > size - 9 && y < 9) ||
      (x < 9 && y > size - 9) ||
      (x === 6 || y === 6) ||
      (x < 9 && y === 8) ||
      (x === 8 && y < 9) ||
      (x > size - 9 && y === 8) ||
      (x === 8 && y > size - 9)
    );
  }
}
