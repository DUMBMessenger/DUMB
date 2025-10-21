import { EventEmitter } from 'events';

export class SSEServer extends EventEmitter {
  constructor() {
    super();
    this.clients = new Set();
  }

  middleware() {
    return (req, res) => {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.flushHeaders();

      const client = {
        res,
        id: Math.random().toString(36).substr(2, 9),
        user: req.user
      };

      this.clients.add(client);
      this.emit('connect', client);

      this.sendToClient(client, { type: 'connected', clientId: client.id });

      req.on('close', () => {
        this.clients.delete(client);
        this.emit('disconnect', client);
      });
    };
  }

  sendToClient(client, data) {
    if (client.res.writable) {
      client.res.write(`data: ${JSON.stringify(data)}\n\n`);
    }
  }

  broadcast(data) {
    this.clients.forEach(client => {
      this.sendToClient(client, data);
    });
  }

  sendToUser(username, data) {
    this.clients.forEach(client => {
      if (client.user === username) {
        this.sendToClient(client, data);
      }
    });
  }
}
