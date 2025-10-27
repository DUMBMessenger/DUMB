import { EventEmitter } from 'events';

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

    const acceptKey = this.generateAccept(key);
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${acceptKey}\r\n\r\n`
    );

    const ws = this.createWebSocket(socket);
    callback(ws);
  }

  generateAccept(key) {
    const crypto = require('crypto');
    const sha1 = crypto.createHash('sha1');
    sha1.update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11');
    return sha1.digest('base64');
  }

  createWebSocket(socket) {
    const ws = {
      socket,
      readyState: 1,
      isAlive: true,
      send: (data) => {
        if (socket.writable) {
          const frame = this.createFrame(typeof data === 'string' ? data : JSON.stringify(data));
          socket.write(frame);
        }
      },
      ping: () => {
        const pingFrame = Buffer.from([0x89, 0x00]);
        socket.write(pingFrame);
      },
      terminate: () => {
        socket.destroy();
      },
      on: (event, handler) => {
        if (event === 'message') {
          socket.on('data', (data) => {
            const message = this.parseFrame(data);
            if (message) handler(message);
          });
        } else {
          socket.on(event, handler);
        }
      }
    };

    this.clients.add(ws);
    socket.on('close', () => {
      ws.readyState = 3;
      this.clients.delete(ws);
    });

    return ws;
  }

  createFrame(data) {
    const buffer = Buffer.from(data, 'utf8');
    const length = buffer.length;
    
    let frame;
    if (length <= 125) {
      frame = Buffer.alloc(2 + length);
      frame[1] = length;
    } else if (length <= 65535) {
      frame = Buffer.alloc(4 + length);
      frame[1] = 126;
      frame.writeUInt16BE(length, 2);
    } else {
      frame = Buffer.alloc(10 + length);
      frame[1] = 127;
      frame.writeBigUInt64BE(BigInt(length), 2);
    }

    frame[0] = 0x81;
    buffer.copy(frame, frame.length - length);
    return frame;
  }

  parseFrame(buffer) {
    if (buffer.length < 2) return null;
    
    const opcode = buffer[0] & 0x0F;
    if (opcode !== 0x01) return null;
    
    const payloadLength = buffer[1] & 0x7F;
    let dataStart = 2;
    
    if (payloadLength === 126) {
      dataStart = 4;
    } else if (payloadLength === 127) {
      dataStart = 10;
    }
    
    const mask = buffer.slice(dataStart, dataStart + 4);
    const payload = buffer.slice(dataStart + 4);
    
    const unmasked = Buffer.alloc(payload.length);
    for (let i = 0; i < payload.length; i++) {
      unmasked[i] = payload[i] ^ mask[i % 4];
    }
    
    return unmasked.toString('utf8');
  }

  broadcast(data) {
    this.clients.forEach(client => {
      if (client.readyState === 1) {
        client.send(JSON.stringify(data));
      }
    });
  }
}
