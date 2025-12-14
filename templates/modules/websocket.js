import { EventEmitter } from 'events';
import crypto from 'crypto';

export class WebSocketServer extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = options;
    this.clients = new Set();
    this.maxBufferSize = options.maxBufferSize || 1024 * 1024;
    
    this.on('error', (error) => {
      console.error('WebSocketServer error:', error.message);
    });
  }

  handleUpgrade(request, socket, head, callback) {
    if (request.method !== 'GET') {
      this.sendHttpError(socket, 405, 'Method Not Allowed');
      return;
    }

    if (request.headers.upgrade?.toLowerCase() !== 'websocket') {
      this.sendHttpError(socket, 400, 'Bad Request');
      return;
    }

    if (request.headers.connection?.toLowerCase().includes('upgrade') === false) {
      this.sendHttpError(socket, 400, 'Bad Request');
      return;
    }

    const key = request.headers['sec-websocket-key'];
    if (!key || key.length !== 24) {
      this.sendHttpError(socket, 400, 'Invalid Sec-WebSocket-Key');
      return;
    }

    try {
      const acceptKey = this.generateAccept(key);
      
      const responseHeaders = [
        'HTTP/1.1 101 Switching Protocols',
        'Upgrade: websocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Accept: ${acceptKey}`,
        '',
        ''
      ].join('\r\n');

      socket.write(responseHeaders);

      const ws = this.createWebSocket(socket, request);
      
      if (callback) {
        callback(ws);
      }
      
      this.emit('connection', ws, request);
      
      if (head && head.length > 0) {
        this.handleSocketData(ws, head);
      }
      
    } catch (error) {
      this.sendHttpError(socket, 500, 'Internal Server Error');
    }
  }

  sendHttpError(socket, code, message) {
    try {
      const response = `HTTP/1.1 ${code} ${message}\r\n\r\n`;
      socket.write(response);
      socket.destroy();
    } catch (error) {}
  }

  generateAccept(key) {
    const magic = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
    const hash = crypto.createHash('sha1');
    hash.update(key + magic);
    return hash.digest('base64');
  }

  createWebSocket(socket, request) {
    const ws = {
      id: Math.random().toString(36).substr(2, 9),
      socket,
      request,
      readyState: 1,
      isAlive: true,
      user: null,
      buffer: Buffer.alloc(0),
      lastActivity: Date.now(),
      
      on: (event, handler) => {
        if (event === 'message') {
          ws.messageHandler = handler;
        } else if (event === 'close') {
          ws.closeHandler = handler;
        } else if (event === 'error') {
          ws.errorHandler = handler;
        }
        socket.on(event, handler);
      },
      
      send: (data) => {
        if (ws.readyState !== 1) {
          return false;
        }

        if (!socket.writable || socket.destroyed) {
          ws.readyState = 3;
          return false;
        }

        try {
          const dataToSend = typeof data === 'string' ? data : JSON.stringify(data);
          const frame = this.createTextFrame(dataToSend);
          return socket.write(frame);
        } catch (error) {
          this.safeHandleClientError(ws, error);
          return false;
        }
      },
      
      ping: () => {
        if (ws.readyState !== 1 || !socket.writable) {
          return false;
        }
        
        try {
          const pingFrame = this.createPingFrame();
          return socket.write(pingFrame);
        } catch (error) {
          return false;
        }
      },
      
      close: (code = 1000, reason = '') => {
        if (ws.readyState !== 1) return;
        
        ws.readyState = 3;
        
        try {
          const closeFrame = this.createCloseFrame(code, reason);
          socket.write(closeFrame);
        } catch (error) {}
        
        setTimeout(() => {
          if (!socket.destroyed) {
            this.safeSocketDestroy(socket);
          }
        }, 5000);
      },
      
      terminate: () => {
        if (ws.readyState === 3) return;
        
        ws.readyState = 3;
        this.safeSocketDestroy(socket);
      }
    };

    socket.on('data', (data) => {
      ws.lastActivity = Date.now();
      this.handleSocketData(ws, data);
    });

    socket.on('close', (hadError) => {
      ws.readyState = 3;
      this.clients.delete(ws);
      
      if (ws.closeHandler) {
        try {
          ws.closeHandler(hadError);
        } catch (error) {}
      }
      
      this.safeEmit('close', ws, hadError);
    });

    socket.on('error', (error) => {
      this.safeHandleClientError(ws, error);
    });

    socket.on('end', () => {
      ws.readyState = 3;
    });

    this.clients.add(ws);
    
    setTimeout(() => {
      if (ws.readyState === 1) {
        const welcomeMsg = {
          type: 'connected', 
          message: 'WebSocket connected successfully',
          timestamp: Date.now(),
          id: ws.id
        };
        
        ws.send(JSON.stringify(welcomeMsg));
      }
    }, 100);
    
    return ws;
  }

  handleSocketData(ws, data) {
    try {
      if (ws.buffer.length + data.length > this.maxBufferSize) {
        ws.close(1009, 'Message too large');
        return;
      }
      
      ws.buffer = Buffer.concat([ws.buffer, data]);
      
      while (ws.buffer.length > 0) {
        const result = this.parseFrame(ws.buffer, ws);
        if (!result) break;
        
        const { message, bytesConsumed } = result;
        ws.buffer = ws.buffer.slice(bytesConsumed);
        
        if (message !== null) {
          if (ws.messageHandler) {
            try {
              ws.messageHandler(message);
            } catch (error) {}
          }
          
          this.safeEmit('message', ws, message);
        }
      }
      
    } catch (error) {
      this.safeHandleClientError(ws, error);
    }
  }

  safeHandleClientError(ws, error) {
    if (ws.errorHandler) {
      try {
        ws.errorHandler(error);
        return;
      } catch (handlerError) {}
    }
    
    this.safeEmit('error', ws, error);
  }

  safeEmit(event, ...args) {
    try {
      if (this.listenerCount(event) > 0) {
        this.emit(event, ...args);
      } else if (event === 'error') {
        console.error('WebSocket error:', args[0]?.message || 'Unknown error');
      }
    } catch (emitError) {}
  }

  safeSocketWrite(socket, data) {
    if (!socket.writable || socket.destroyed) {
      return false;
    }
    
    try {
      return socket.write(data);
    } catch (error) {
      return false;
    }
  }

  safeSocketDestroy(socket) {
    if (socket.destroyed) return;
    
    try {
      socket.destroy();
    } catch (error) {}
  }

  createTextFrame(data) {
    return this.createFrame(data, 0x81);
  }

  createPingFrame() {
    return this.createFrame('', 0x89);
  }

  createPongFrame() {
    return this.createFrame('', 0x8A);
  }

  createFrame(payload, opcode) {
    const payloadBuffer = Buffer.from(payload, 'utf8');
    const payloadLength = payloadBuffer.length;
    
    let headerLength = 2;
    let lengthByte;
    
    if (payloadLength <= 125) {
      lengthByte = payloadLength;
    } else if (payloadLength <= 65535) {
      headerLength += 2;
      lengthByte = 126;
    } else {
      headerLength += 8;
      lengthByte = 127;
    }
    
    const frame = Buffer.alloc(headerLength + payloadLength);
    
    frame[0] = opcode;
    frame[1] = lengthByte;
    
    let offset = 2;
    
    if (lengthByte === 126) {
      frame.writeUInt16BE(payloadLength, offset);
      offset += 2;
    } else if (lengthByte === 127) {
      frame.writeBigUInt64BE(BigInt(payloadLength), offset);
      offset += 8;
    }
    
    payloadBuffer.copy(frame, offset);
    
    return frame;
  }

  createCloseFrame(code = 1000, reason = '') {
    const reasonBuffer = Buffer.from(reason, 'utf8');
    const payload = Buffer.alloc(2 + reasonBuffer.length);
    
    payload.writeUInt16BE(code, 0);
    reasonBuffer.copy(payload, 2);
    
    return this.createFrame(payload, 0x88);
  }

  parseFrame(buffer, ws) {
    if (buffer.length < 2) {
      return null;
    }
    
    const firstByte = buffer[0];
    const secondByte = buffer[1];
    
    const opcode = firstByte & 0x0F;
    const isMasked = Boolean(secondByte & 0x80);
    let payloadLength = secondByte & 0x7F;
    
    let currentOffset = 2;
    
    if (payloadLength === 126) {
      if (buffer.length < 4) return null;
      payloadLength = buffer.readUInt16BE(2);
      currentOffset = 4;
    } else if (payloadLength === 127) {
      if (buffer.length < 10) return null;
      payloadLength = Number(buffer.readBigUInt64BE(2));
      currentOffset = 10;
    }
    
    if (payloadLength > this.maxBufferSize) {
      ws.close(1009, 'Frame too large');
      return null;
    }
    
    if (isMasked) {
      if (buffer.length < currentOffset + 4) return null;
      currentOffset += 4;
    }
    
    const totalFrameLength = currentOffset + payloadLength;
    if (buffer.length < totalFrameLength) {
      return null;
    }
    
    const payload = buffer.slice(currentOffset, totalFrameLength);
    
    let unmaskedPayload = payload;
    if (isMasked) {
      const maskingKey = buffer.slice(currentOffset - 4, currentOffset);
      unmaskedPayload = Buffer.alloc(payloadLength);
      for (let i = 0; i < payloadLength; i++) {
        unmaskedPayload[i] = payload[i] ^ maskingKey[i % 4];
      }
    }
    
    switch (opcode) {
      case 0x01:
        try {
          const text = unmaskedPayload.toString('utf8');
          return { 
            message: text, 
            bytesConsumed: totalFrameLength 
          };
        } catch (error) {
          return { message: null, bytesConsumed: totalFrameLength };
        }
      
      case 0x08:
        let closeCode = 1000;
        let closeReason = '';
        
        if (unmaskedPayload.length >= 2) {
          closeCode = unmaskedPayload.readUInt16BE(0);
          closeReason = unmaskedPayload.slice(2).toString('utf8');
        }
        
        ws.close(closeCode, closeReason);
        return { message: null, bytesConsumed: totalFrameLength };
      
      case 0x09:
        const pongFrame = this.createPongFrame();
        this.safeSocketWrite(ws.socket, pongFrame);
        return { message: null, bytesConsumed: totalFrameLength };
      
      case 0x0A:
        ws.isAlive = true;
        return { message: null, bytesConsumed: totalFrameLength };
      
      default:
        return { message: null, bytesConsumed: totalFrameLength };
    }
  }

  broadcast(data, filter = null) {
    const dataToSend = typeof data === 'string' ? data : JSON.stringify(data);
    let successCount = 0;
    let errorCount = 0;
    
    this.clients.forEach(client => {
      if (client.readyState === 1 && (!filter || filter(client))) {
        if (client.send(dataToSend)) {
          successCount++;
        } else {
          errorCount++;
        }
      }
    });
    
    return { success: successCount, errors: errorCount };
  }

  sendToUser(username, data) {
    return this.broadcast(data, client => client.user === username);
  }

  getClientCount() {
    return this.clients.size;
  }

  cleanup() {
    const now = Date.now();
    const maxInactivity = 5 * 60 * 1000;
    
    this.clients.forEach(client => {
      if (client.readyState === 1 && (now - client.lastActivity > maxInactivity)) {
        client.close(1000, 'Connection timeout');
      }
    });
  }
}
