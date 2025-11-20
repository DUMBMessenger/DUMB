import { EventEmitter } from 'events';
import crypto from 'crypto';

export class WebSocketServer extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = options;
    this.clients = new Set();
  }

  handleUpgrade(request, socket, head, callback) {
    const key = request.headers['sec-websocket-key'];
    if (!key) {
      socket.destroy();
      return;
    }

    try {
      const acceptKey = this.generateAccept(key);
      
      const responseHeaders = [
        'HTTP/1.1 101 Switching Protocols',
        'Upgrade: websocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Accept: ${acceptKey}`,
        '\r\n'
      ].join('\r\n');

      socket.write(responseHeaders);

      const ws = this.createWebSocket(socket, request);
      callback(ws);
      
      if (head && head.length > 0) {
        this.handleSocketData(ws, head);
      }
      
    } catch (error) {
      console.error('WebSocket upgrade error:', error);
      socket.destroy();
    }
  }

  generateAccept(key) {
    const sha1 = crypto.createHash('sha1');
    sha1.update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11');
    return sha1.digest('base64');
  }

  createWebSocket(socket, request) {
    const ws = {
      socket,
      request,
      readyState: 1,
      isAlive: true,
      user: null,
      buffer: Buffer.alloc(0),
      
      on: (event, handler) => {
        if (event === 'message') {
          ws.messageHandler = handler;
        }
        socket.on(event, handler);
      },
      
      send: (data) => {
        if (socket.writable && ws.readyState === 1) {
          try {
            const dataToSend = typeof data === 'string' ? data : JSON.stringify(data);
            const frame = this.createFrame(dataToSend);
            socket.write(frame);
          } catch (error) {
            console.error('WebSocket send error:', error);
          }
        }
      },
      
      ping: () => {
        if (socket.writable && ws.readyState === 1) {
          const pingFrame = this.createFrame('', 0x89);
          socket.write(pingFrame);
        }
      },
      
      close: (code = 1000, reason = '') => {
        if (ws.readyState !== 1) return;
        
        ws.readyState = 3;
        try {
          const closeFrame = this.createCloseFrame(code, reason);
          socket.write(closeFrame);
        } catch (error) {}
        setTimeout(() => socket.destroy(), 1000);
      },
      
      terminate: () => {
        ws.readyState = 3;
        socket.destroy();
      }
    };

    socket.on('data', (data) => {
      this.handleSocketData(ws, data);
    });

    socket.on('close', (hadError) => {
      ws.readyState = 3;
      this.clients.delete(ws);
      this.emit('close', ws);
    });

    socket.on('error', (error) => {
      console.error('WebSocket socket error:', error);
      this.emit('error', ws, error);
    });

    this.clients.add(ws);
    
    setTimeout(() => {
      if (ws.readyState === 1) {
        ws.send(JSON.stringify({ 
          type: 'connected', 
          message: 'WebSocket connected successfully',
          timestamp: Date.now()
        }));
      }
    }, 100);
    
    return ws;
  }

  handleSocketData(ws, data) {
    try {
      ws.buffer = Buffer.concat([ws.buffer, data]);
      
      while (ws.buffer.length > 0) {
        const result = this.parseFrame(ws.buffer, ws);
        if (!result) break;
        
        const { message, bytesConsumed } = result;
        ws.buffer = ws.buffer.slice(bytesConsumed);
        
        if (message !== null) {
          if (ws.messageHandler) {
            ws.messageHandler(message);
          }
          
          this.emit('message', ws, message);
        }
      }
    } catch (error) {
      console.error('WebSocket data handling error:', error);
    }
  }

  createFrame(data, opcode = 0x81) {
    const buffer = Buffer.from(data, 'utf8');
    const payloadLength = buffer.length;
    
    let headerLength = 2;
    let lengthBytes = 0;
    
    if (payloadLength <= 125) {
      lengthBytes = 0;
    } else if (payloadLength <= 65535) {
      headerLength += 2;
      lengthBytes = 126;
    } else {
      headerLength += 8;
      lengthBytes = 127;
    }
    
    const frame = Buffer.alloc(headerLength + payloadLength);
    
    frame[0] = opcode;
    frame[1] = lengthBytes;
    
    let offset = 2;
    if (lengthBytes === 126) {
      frame.writeUInt16BE(payloadLength, offset);
      offset += 2;
    } else if (lengthBytes === 127) {
      frame.writeBigUInt64BE(BigInt(payloadLength), offset);
      offset += 8;
    } else {
      frame[1] = payloadLength;
    }
    
    buffer.copy(frame, offset);
    
    return frame;
  }

  createCloseFrame(code = 1000, reason = '') {
    const reasonBuffer = Buffer.from(reason, 'utf8');
    const payloadLength = 2 + reasonBuffer.length;
    
    let headerLength = 2;
    let lengthBytes = payloadLength;
    
    if (payloadLength > 125) {
      headerLength += 2;
      lengthBytes = 126;
    }
    
    const frame = Buffer.alloc(headerLength + payloadLength);
    
    frame[0] = 0x88;
    frame[1] = lengthBytes;
    
    let offset = 2;
    if (lengthBytes === 126) {
      frame.writeUInt16BE(payloadLength, offset);
      offset += 2;
    }
    
    frame.writeUInt16BE(code, offset);
    offset += 2;
    
    reasonBuffer.copy(frame, offset);
    
    return frame;
  }

  parseFrame(buffer, ws) {
    if (buffer.length < 2) return null;
    
    const firstByte = buffer[0];
    const secondByte = buffer[1];
    
    const opcode = firstByte & 0x0F;
    const isMasked = (secondByte & 0x80) !== 0;
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
        return { message: null, bytesConsumed: totalFrameLength };
      
      case 0x09:
        const pongFrame = this.createFrame('', 0x8A);
        ws.socket.write(pongFrame);
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
    
    this.clients.forEach(client => {
      if (client.readyState === 1 && (!filter || filter(client))) {
        try {
          client.send(dataToSend);
        } catch (error) {
          console.error('Broadcast error to client:', error);
        }
      }
    });
  }

  sendToUser(username, data) {
    this.broadcast(data, client => client.user === username);
  }
}
