import { EventEmitter } from 'events';
import { Crypto } from './crypto.js';

export class NotificationService extends EventEmitter {
  constructor(storage, wss, sse) {
    super();
    this.storage = storage;
    this.wss = wss;
    this.sse = sse;
    this.subscriptions = new Map(); // userId -> Set<subscriptionId>
    this.pushSubscriptions = new Map(); // userId -> pushSubscription[]
    this.notificationQueue = new Map(); // userId -> notification[]
    this.setupWebSocketHandlers();
    this.setupSSEHandlers();
  }

  setupWebSocketHandlers() {
    if (this.wss) {
      this.wss.on('connection', (ws) => {
        ws.on('message', (data) => {
          try {
            const message = JSON.parse(data);
            this.handleWebSocketMessage(ws, message);
          } catch (error) {
            console.error('Invalid WebSocket message:', error);
          }
        });

        ws.on('close', () => {
          this.emit('websocketDisconnected', { userId: ws.user });
        });
      });
    }
  }

  setupSSEHandlers() {
    if (this.sse) {
      this.sse.on('connect', (client) => {
        this.emit('sseConnected', { userId: client.user, clientId: client.id });
      });

      this.sse.on('disconnect', (client) => {
        this.emit('sseDisconnected', { userId: client.user, clientId: client.id });
      });
    }
  }

  handleWebSocketMessage(ws, message) {
    switch (message.type) {
      case 'subscribe':
        this.handleSubscribe(ws, message);
        break;
      case 'unsubscribe':
        this.handleUnsubscribe(ws, message);
        break;
      case 'mark_read':
        this.handleMarkRead(ws, message);
        break;
      case 'get_notifications':
        this.handleGetNotifications(ws, message);
        break;
      default:
        console.warn('Unknown WebSocket message type:', message.type);
    }
  }

  async handleSubscribe(ws, message) {
    if (message.subscription && ws.user) {
      try {
        const subId = await this.subscribeUser(ws.user, message.subscription);
        ws.send(JSON.stringify({
          type: 'subscription_result',
          success: true,
          subscriptionId: subId
        }));
      } catch (error) {
        ws.send(JSON.stringify({
          type: 'subscription_result',
          success: false,
          error: error.message
        }));
      }
    }
  }

  async handleUnsubscribe(ws, message) {
    if (message.subscriptionId && ws.user) {
      const success = await this.unsubscribeUser(ws.user, message.subscriptionId);
      ws.send(JSON.stringify({
        type: 'unsubscription_result',
        success,
        subscriptionId: message.subscriptionId
      }));
    }
  }

  async handleMarkRead(ws, message) {
    if (message.notificationId && ws.user) {
      await this.markAsRead(ws.user, message.notificationId);
      ws.send(JSON.stringify({
        type: 'mark_read_result',
        success: true,
        notificationId: message.notificationId
      }));
    } else if (message.all && ws.user) {
      await this.markAllAsRead(ws.user);
      ws.send(JSON.stringify({
        type: 'mark_all_read_result',
        success: true
      }));
    }
  }

  async handleGetNotifications(ws, message) {
    if (ws.user) {
      const options = message.options || {};
      const notifications = await this.getNotifications(ws.user, options);
      ws.send(JSON.stringify({
        type: 'notifications',
        notifications,
        hasMore: notifications.length === (options.limit || 50)
      }));
    }
  }

  async subscribeUser(userId, subscription) {
    if (!this.subscriptions.has(userId)) {
      this.subscriptions.set(userId, new Set());
    }
    if (!this.pushSubscriptions.has(userId)) {
      this.pushSubscriptions.set(userId, []);
    }

    const subId = Crypto.randomBytes(16).toString('hex');
    this.subscriptions.get(userId).add(subId);

    const pushSub = {
      id: subId,
      endpoint: subscription.endpoint,
      keys: subscription.keys,
      userAgent: subscription.userAgent,
      createdAt: Date.now(),
      expires: subscription.expires || Date.now() + (30 * 24 * 60 * 60 * 1000), // 30 days default
      errorCount: 0,
      lastError: null
    };

    this.pushSubscriptions.get(userId).push(pushSub);
    
    await this.storage.savePushSubscription(userId, pushSub);

    this.emit('subscriptionAdded', { userId, subscription: pushSub });
    return subId;
  }

  async unsubscribeUser(userId, subscriptionId) {
    const userSubs = this.subscriptions.get(userId);
    if (userSubs) {
      userSubs.delete(subscriptionId);
    }

    const pushSubs = this.pushSubscriptions.get(userId);
    if (pushSubs) {
      const index = pushSubs.findIndex(sub => sub.id === subscriptionId);
      if (index !== -1) {
        const removed = pushSubs.splice(index, 1)[0];
        await this.storage.deletePushSubscription(userId, subscriptionId);
        this.emit('subscriptionRemoved', { userId, subscription: removed });
        return true;
      }
    }
    return false;
  }

  async getUserSubscriptions(userId) {
    return this.pushSubscriptions.get(userId) || [];
  }

  async sendNotification(userId, notification) {
    const notificationId = Crypto.randomBytes(16).toString('hex');
    const fullNotification = {
      id: notificationId,
      userId,
      type: notification.type || 'message',
      title: notification.title,
      body: notification.body,
      data: notification.data || {},
      image: notification.image,
      icon: notification.icon,
      badge: notification.badge,
      tag: notification.tag,
      timestamp: Date.now(),
      read: false,
      expires: notification.expires || Date.now() + (7 * 24 * 60 * 60 * 1000), // 7 days
      priority: notification.priority || 'normal',
      actions: notification.actions || []
    };

    await this.storage.saveNotification(fullNotification);

    const realTimeDelivered = await this.deliverRealTime(userId, fullNotification);
    
    if (!realTimeDelivered) {
      this.queueNotification(userId, fullNotification);
    }

    this.emit('notificationSent', { 
      userId, 
      notification: fullNotification, 
      realTime: realTimeDelivered 
    });
    
    return notificationId;
  }

  async deliverRealTime(userId, notification) {
    let delivered = false;

    if (this.wss && this.wss.clients) {
      this.wss.clients.forEach(client => {
        if (client.user === userId && client.readyState === 1) {
          try {
            client.send(JSON.stringify({
              type: 'notification',
              action: 'new',
              notification: {
                id: notification.id,
                type: notification.type,
                title: notification.title,
                body: notification.body,
                data: notification.data,
                timestamp: notification.timestamp,
                priority: notification.priority
              }
            }));
            delivered = true;
          } catch (error) {
            console.error('WebSocket delivery failed:', error);
          }
        }
      });
    }

    if (this.sse && !delivered) {
      delivered = await this.deliverSSE(userId, notification);
    }

    return delivered;
  }

  async deliverSSE(userId, notification) {
    if (!this.sse) return false;

    try {
      this.sse.sendToUser(userId, {
        type: 'notification',
        action: 'new',
        notification: {
          id: notification.id,
          type: notification.type,
          title: notification.title,
          body: notification.body,
          data: notification.data,
          timestamp: notification.timestamp
        }
      });
      return true;
    } catch (error) {
      console.error('SSE delivery failed:', error);
      return false;
    }
  }

  queueNotification(userId, notification) {
    if (!this.notificationQueue.has(userId)) {
      this.notificationQueue.set(userId, []);
    }
    
    const queue = this.notificationQueue.get(userId);
    queue.push(notification);
    
    if (queue.length > 100) {
      queue.shift();
    }
    
    this.processNotificationQueue(userId);
  }

  async processNotificationQueue(userId) {
    const queue = this.notificationQueue.get(userId);
    if (!queue || queue.length === 0) return;

    const subscriptions = await this.getUserSubscriptions(userId);
    const currentTime = Date.now();

    for (const notification of [...queue]) {
      let delivered = false;
      
      for (const subscription of subscriptions) {
        if (subscription.expires > currentTime && subscription.errorCount < 5) {
          try {
            await this.deliverPushNotification(subscription, notification);
            delivered = true;
            const index = queue.findIndex(n => n.id === notification.id);
            if (index !== -1) {
              queue.splice(index, 1);
            }
            break;
          } catch (error) {
            console.error('Push delivery failed:', error);
            subscription.lastError = error.message;
            subscription.errorCount = (subscription.errorCount || 0) + 1;
            
            if (subscription.errorCount >= 5) {
              await this.unsubscribeUser(userId, subscription.id);
            }
          }
        }
      }

      if (!delivered && notification.expires < currentTime) {
        const index = queue.findIndex(n => n.id === notification.id);
        if (index !== -1) {
          queue.splice(index, 1);
        }
      }
    }

    await this.cleanupExpiredSubscriptions(userId);
  }

  async deliverPushNotification(subscription, notification) {
    const payload = {
      title: notification.title,
      body: notification.body,
      icon: notification.icon,
      image: notification.image,
      badge: notification.badge,
      tag: notification.tag,
      data: notification.data,
      timestamp: notification.timestamp,
      actions: notification.actions || [],
      requireInteraction: notification.priority === 'high'
    };

    if (subscription.endpoint && subscription.keys) {
      return await this.sendWebPush(subscription, payload);
    }

    throw new Error('Unsupported push subscription type');
  }

  async sendWebPush(subscription, payload) {
    try {
      const response = await fetch(subscription.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'TTL': '3600',
          'Urgency': payload.priority === 'high' ? 'high' : 'normal'
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error(`Push service responded with ${response.status}`);
      }

      return true;
    } catch (error) {
      throw new Error(`Push delivery failed: ${error.message}`);
    }
  }

  async markAsRead(userId, notificationId) {
    await this.storage.markNotificationAsRead(userId, notificationId);
    
    await this.notifyReadStatus(userId, notificationId);
    
    this.emit('notificationRead', { userId, notificationId });
  }

  async markAllAsRead(userId) {
    await this.storage.markAllNotificationsAsRead(userId);
    
    await this.notifyAllReadStatus(userId);
    
    this.emit('allNotificationsRead', { userId });
  }

  async notifyReadStatus(userId, notificationId) {
    if (this.wss && this.wss.clients) {
      this.wss.clients.forEach(client => {
        if (client.user === userId && client.readyState === 1) {
          client.send(JSON.stringify({
            type: 'notification',
            action: 'read',
            notificationId
          }));
        }
      });
    }

    if (this.sse) {
      this.sse.sendToUser(userId, {
        type: 'notification',
        action: 'read',
        notificationId
      });
    }
  }

  async notifyAllReadStatus(userId) {
    if (this.wss && this.wss.clients) {
      this.wss.clients.forEach(client => {
        if (client.user === userId && client.readyState === 1) {
          client.send(JSON.stringify({
            type: 'notification',
            action: 'all_read'
          }));
        }
      });
    }

    if (this.sse) {
      this.sse.sendToUser(userId, {
        type: 'notification',
        action: 'all_read'
      });
    }
  }

  async getNotifications(userId, options = {}) {
    const { limit = 50, offset = 0, unreadOnly = false, types = [] } = options;
    return await this.storage.getUserNotifications(userId, { limit, offset, unreadOnly, types });
  }

  async getUnreadCount(userId) {
    return await this.storage.getUnreadNotificationCount(userId);
  }

  async deleteNotification(userId, notificationId) {
    await this.storage.deleteNotification(userId, notificationId);
    this.emit('notificationDeleted', { userId, notificationId });
  }

  async cleanupExpiredSubscriptions(userId = null) {
    const currentTime = Date.now();
    
    if (userId) {
      const subscriptions = this.pushSubscriptions.get(userId) || [];
      const validSubscriptions = subscriptions.filter(sub => sub.expires > currentTime);
      
      if (validSubscriptions.length !== subscriptions.length) {
        this.pushSubscriptions.set(userId, validSubscriptions);
        await this.storage.cleanupExpiredSubscriptions(userId, currentTime);
      }
    } else {
      for (const [uid, subscriptions] of this.pushSubscriptions.entries()) {
        const validSubscriptions = subscriptions.filter(sub => sub.expires > currentTime);
        this.pushSubscriptions.set(uid, validSubscriptions);
        await this.storage.cleanupExpiredSubscriptions(uid, currentTime);
      }
    }
  }

  async cleanupExpiredNotifications() {
    await this.storage.cleanupExpiredNotifications();
  }

  async subscribeToChannel(userId, channelId, types = ['message', 'mention']) {
    await this.storage.saveChannelSubscription(userId, channelId, types);
    this.emit('channelSubscribed', { userId, channelId, types });
  }

  async unsubscribeFromChannel(userId, channelId) {
    await this.storage.deleteChannelSubscription(userId, channelId);
    this.emit('channelUnsubscribed', { userId, channelId });
  }

  async getChannelSubscriptions(userId) {
    return await this.storage.getUserChannelSubscriptions(userId);
  }

  async onNewMessage(message) {
    const channelId = message.channel;
    const senderId = message.from;
    
    const members = await this.storage.getChannelMembers(channelId);
    
    for (const member of members) {
      if (member.username !== senderId) {
        const subscriptions = await this.storage.getUserChannelSubscriptions(member.username);
        const channelSub = subscriptions.find(sub => sub.channelId === channelId);
        
        if (channelSub && channelSub.types.includes('message')) {
          await this.sendNotification(member.username, {
            type: 'message',
            title: `New message in ${channelId}`,
            body: `${senderId}: ${message.text?.substring(0, 100) || 'New message'}`,
            data: {
              channelId,
              messageId: message.id,
              senderId,
              action: 'open_channel'
            },
            tag: `channel_${channelId}`,
            priority: message.priority || 'normal'
          });
        }
      }
    }
  }

  async onMention(userId, mentionedBy, message, channelId) {
    await this.sendNotification(userId, {
      type: 'mention',
      title: `You were mentioned in ${channelId}`,
      body: `${mentionedBy}: ${message.text?.substring(0, 100) || ''}`,
      data: {
        channelId,
        messageId: message.id,
        mentionedBy,
        action: 'open_message'
      },
      tag: `mention_${channelId}`,
      priority: 'high'
    });
  }

  async onDirectMessage(receiverId, senderId, message) {
    await this.sendNotification(receiverId, {
      type: 'direct_message',
      title: `Message from ${senderId}`,
      body: message.text?.substring(0, 100) || 'New message',
      data: {
        senderId,
        messageId: message.id,
        action: 'open_direct_chat'
      },
      tag: `dm_${senderId}`,
      priority: 'high'
    });
  }

  async onSystemEvent(userId, event) {
    await this.sendNotification(userId, {
      type: 'system',
      title: event.title,
      body: event.body,
      data: event.data,
      priority: event.priority || 'normal'
    });
  }

  getStats() {
    const totalSubscriptions = Array.from(this.subscriptions.values()).reduce((sum, set) => sum + set.size, 0);
    const queuedNotifications = Array.from(this.notificationQueue.values()).reduce((sum, queue) => sum + queue.length, 0);
    
    return {
      totalSubscriptions,
      totalUsers: this.subscriptions.size,
      queuedNotifications,
      activeWebSocketConnections: this.wss ? this.wss.clients.size : 0,
      activeSSEConnections: this.sse ? this.sse.clients.size : 0
    };
  }

  async sendBulkNotifications(userIds, notification) {
    const results = [];
    
    for (const userId of userIds) {
      try {
        const notificationId = await this.sendNotification(userId, notification);
        results.push({ userId, success: true, notificationId });
      } catch (error) {
        results.push({ userId, success: false, error: error.message });
      }
    }
    
    return results;
  }

  async sendHighPriorityNotification(userId, notification) {
    return await this.sendNotification(userId, {
      ...notification,
      priority: 'high'
    });
  }

  async sendWelcomeNotification(userId) {
    return await this.sendNotification(userId, {
      type: 'system',
      title: 'Welcome!',
      body: 'Thank you for joining our service!',
      data: { action: 'open_welcome' },
      priority: 'normal'
    });
  }
}

export class NotificationManager {
  constructor(storage, wss, sse) {
    this.service = new NotificationService(storage, wss, sse);
    this.setupPeriodicCleanup();
  }

  setupPeriodicCleanup() {
    setInterval(() => {
      this.service.cleanupExpiredSubscriptions();
      this.service.cleanupExpiredNotifications();
    }, 60 * 60 * 1000);

    setInterval(() => {
      for (const userId of this.service.notificationQueue.keys()) {
        this.service.processNotificationQueue(userId);
      }
    }, 5 * 60 * 1000);
  }

  getService() {
    return this.service;
  }

  middleware() {
    return (req, res, next) => {
      req.notifications = this.service;
      next();
    };
  }

  setupRoutes(app) {
    app.post('/api/notifications/subscribe', this.handleSubscribe.bind(this));
    app.post('/api/notifications/unsubscribe', this.handleUnsubscribe.bind(this));
    app.get('/api/notifications', this.handleGetNotifications.bind(this));
    app.put('/api/notifications/read', this.handleMarkRead.bind(this));
    app.get('/api/notifications/stats', this.handleGetStats.bind(this));
  }

  async handleSubscribe(req, res) {
    try {
      const { userId, subscription } = req.body;
      const subId = await this.service.subscribeUser(userId, subscription);
      res.json({ success: true, subscriptionId: subId });
    } catch (error) {
      res.status(400).json({ success: false, error: error.message });
    }
  }

  async handleUnsubscribe(req, res) {
    try {
      const { userId, subscriptionId } = req.body;
      const success = await this.service.unsubscribeUser(userId, subscriptionId);
      res.json({ success });
    } catch (error) {
      res.status(400).json({ success: false, error: error.message });
    }
  }

  async handleGetNotifications(req, res) {
    try {
      const userId = req.user.id;
      const options = req.query;
      const notifications = await this.service.getNotifications(userId, options);
      res.json({ success: true, notifications });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  }

  async handleMarkRead(req, res) {
    try {
      const userId = req.user.id;
      const { notificationId, all } = req.body;
      
      if (all) {
        await this.service.markAllAsRead(userId);
        res.json({ success: true });
      } else {
        await this.service.markAsRead(userId, notificationId);
        res.json({ success: true });
      }
    } catch (error) {
      res.status(400).json({ success: false, error: error.message });
    }
  }

  async handleGetStats(req, res) {
    try {
      const stats = this.service.getStats();
      res.json({ success: true, stats });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  }
}
