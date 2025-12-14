import { EventEmitter } from 'events';
import crypto from 'crypto';

/**
 * DCP (Debianrose's Call Protocol) - Simplified call protocol over WebSocket
 * Supports both audio and video calls with minimal dependencies
 */
export class DCPProtocol extends EventEmitter {
    constructor(server, config = {}) {
        super();
        this.server = server;
        this.config = {
            keepAliveInterval: 30000, // 30 seconds
            sessionTimeout: 300000,   // 5 minutes
            pingTimeout: 10000,       // 10 seconds
            maxParticipants: 10,
            ...config
        };
        
        this.activeCalls = new Map(); // callId -> call info
        this.userConnections = new Map(); // username -> ws connection
        this.keepAliveTimers = new Map(); // callId -> interval
        
        this.setupWebSocketHandlers();
    }

    setupWebSocketHandlers() {
        this.server.on('connection', (ws, req) => {
            this.handleConnection(ws, req);
        });
    }

    handleConnection(ws, req) {
        // Extract user from WebSocket connection (assumes user is attached during auth)
        const user = ws.user;
        if (!user) {
            ws.close(1008, 'Authentication required');
            return;
        }

        // Store user connection
        this.userConnections.set(user, ws);

        // Handle incoming DCP messages
        ws.on('message', (data) => {
            try {
                const message = JSON.parse(data);
                this.handleDCPMessage(user, ws, message);
            } catch (error) {
                this.sendError(ws, 'INVALID_MESSAGE', 'Invalid JSON format');
            }
        });

        // Handle disconnection
        ws.on('close', () => {
            this.handleDisconnection(user);
        });

        // Send connection confirmation
        this.send(ws, {
            type: 'dcp_connected',
            success: true,
            message: 'DCP protocol ready',
            timestamp: Date.now()
        });
    }

    handleDCPMessage(user, ws, message) {
        const { type, callId, target, data, sdp, candidate } = message;

        switch (type) {
            case 'call_initiate':
                this.handleCallInitiate(user, ws, message);
                break;
            
            case 'call_accept':
                this.handleCallAccept(user, ws, message);
                break;
            
            case 'call_reject':
                this.handleCallReject(user, ws, message);
                break;
            
            case 'call_end':
                this.handleCallEnd(user, ws, message);
                break;
            
            case 'sdp_offer':
                this.handleSDPOffer(user, ws, message);
                break;
            
            case 'sdp_answer':
                this.handleSDPAnswer(user, ws, message);
                break;
            
            case 'ice_candidate':
                this.handleICECandidate(user, ws, message);
                break;
            
            case 'keep_alive':
                this.handleKeepAlive(user, ws, message);
                break;
            
            case 'call_status':
                this.handleCallStatus(user, ws, message);
                break;
            
            case 'mute_audio':
            case 'mute_video':
                this.handleMediaControl(user, ws, message);
                break;
            
            default:
                this.sendError(ws, 'UNKNOWN_TYPE', `Unknown message type: ${type}`);
        }
    }

    /**
     * Initiate a new call
     */
    async handleCallInitiate(caller, ws, message) {
        const { target, channel, callType = 'audio', metadata = {} } = message;
        
        // Validate target user
        if (!target || target === caller) {
            return this.sendError(ws, 'INVALID_TARGET', 'Invalid target user');
        }

        // Check if target is online
        const targetWs = this.userConnections.get(target);
        if (!targetWs) {
            return this.sendError(ws, 'USER_OFFLINE', 'Target user is offline');
        }

        // Check if caller is already in a call
        for (const [callId, call] of this.activeCalls) {
            if (call.participants.includes(caller)) {
                return this.sendError(ws, 'ALREADY_IN_CALL', 'You are already in a call');
            }
        }

        // Generate unique call ID
        const callId = `dcp_${crypto.randomBytes(8).toString('hex')}`;

        // Create call session
        const call = {
            id: callId,
            caller,
            target,
            channel: channel || null,
            type: callType,
            status: 'ringing',
            participants: [caller],
            metadata,
            createdAt: Date.now(),
            lastActivity: Date.now(),
            sdpExchange: {
                offer: null,
                answer: null
            },
            iceCandidates: []
        };

        this.activeCalls.set(callId, call);

        // Send call invitation to target
        this.send(targetWs, {
            type: 'call_incoming',
            callId,
            caller,
            channel,
            callType,
            metadata,
            timestamp: Date.now()
        });

        // Send confirmation to caller
        this.send(ws, {
            type: 'call_initiated',
            callId,
            target,
            status: 'ringing',
            timestamp: Date.now()
        });

        // Start ringing timeout (30 seconds)
        setTimeout(() => {
            const currentCall = this.activeCalls.get(callId);
            if (currentCall && currentCall.status === 'ringing') {
                this.endCall(callId, 'timeout', 'Call timed out');
            }
        }, 30000);
    }

    /**
     * Accept an incoming call
     */
    handleCallAccept(user, ws, message) {
        const { callId } = message;
        
        const call = this.activeCalls.get(callId);
        if (!call) {
            return this.sendError(ws, 'CALL_NOT_FOUND', 'Call not found or expired');
        }

        if (call.target !== user) {
            return this.sendError(ws, 'NOT_AUTHORIZED', 'You are not the target of this call');
        }

        if (call.status !== 'ringing') {
            return this.sendError(ws, 'INVALID_STATUS', 'Call is not ringing');
        }

        // Update call status
        call.status = 'active';
        call.participants.push(user);
        call.lastActivity = Date.now();

        // Send acceptance to caller
        const callerWs = this.userConnections.get(call.caller);
        if (callerWs) {
            this.send(callerWs, {
                type: 'call_accepted',
                callId,
                target: user,
                timestamp: Date.now()
            });
        }

        // Send confirmation to acceptor
        this.send(ws, {
            type: 'call_accepted_confirmation',
            callId,
            timestamp: Date.now()
        });

        // Start keep-alive for this call
        this.startKeepAlive(callId);
    }

    /**
     * Reject an incoming call
     */
    handleCallReject(user, ws, message) {
        const { callId, reason = 'User rejected' } = message;
        
        const call = this.activeCalls.get(callId);
        if (!call) return;

        if (call.target !== user) {
            return this.sendError(ws, 'NOT_AUTHORIZED', 'You are not the target of this call');
        }

        // Send rejection to caller
        const callerWs = this.userConnections.get(call.caller);
        if (callerWs) {
            this.send(callerWs, {
                type: 'call_rejected',
                callId,
                reason,
                timestamp: Date.now()
            });
        }

        // Clean up call
        this.cleanupCall(callId, 'rejected', reason);
    }

    /**
     * End an active call
     */
    handleCallEnd(user, ws, message) {
        const { callId, reason = 'User ended call' } = message;
        
        const call = this.activeCalls.get(callId);
        if (!call) return;

        if (!call.participants.includes(user)) {
            return this.sendError(ws, 'NOT_PARTICIPANT', 'You are not a participant in this call');
        }

        this.endCall(callId, user, reason);
    }

    /**
     * Handle SDP offer
     */
    handleSDPOffer(user, ws, message) {
        const { callId, sdp } = message;
        
        const call = this.activeCalls.get(callId);
        if (!call || !call.participants.includes(user)) {
            return this.sendError(ws, 'INVALID_CALL', 'Call not found or not authorized');
        }

        // Store SDP offer
        call.sdpExchange.offer = {
            sdp,
            from: user,
            timestamp: Date.now()
        };

        // Forward to other participant(s)
        call.participants.forEach(participant => {
            if (participant !== user) {
                const participantWs = this.userConnections.get(participant);
                if (participantWs) {
                    this.send(participantWs, {
                        type: 'sdp_offer',
                        callId,
                        sdp,
                        from: user,
                        timestamp: Date.now()
                    });
                }
            }
        });
    }

    /**
     * Handle SDP answer
     */
    handleSDPAnswer(user, ws, message) {
        const { callId, sdp } = message;
        
        const call = this.activeCalls.get(callId);
        if (!call || !call.participants.includes(user)) {
            return this.sendError(ws, 'INVALID_CALL', 'Call not found or not authorized');
        }

        // Store SDP answer
        call.sdpExchange.answer = {
            sdp,
            from: user,
            timestamp: Date.now()
        };

        // Forward to other participant(s)
        call.participants.forEach(participant => {
            if (participant !== user) {
                const participantWs = this.userConnections.get(participant);
                if (participantWs) {
                    this.send(participantWs, {
                        type: 'sdp_answer',
                        callId,
                        sdp,
                        from: user,
                        timestamp: Date.now()
                    });
                }
            }
        });
    }

    /**
     * Handle ICE candidate
     */
    handleICECandidate(user, ws, message) {
        const { callId, candidate } = message;
        
        const call = this.activeCalls.get(callId);
        if (!call || !call.participants.includes(user)) {
            return this.sendError(ws, 'INVALID_CALL', 'Call not found or not authorized');
        }

        // Store ICE candidate
        call.iceCandidates.push({
            candidate,
            from: user,
            timestamp: Date.now()
        });

        // Forward to other participant(s)
        call.participants.forEach(participant => {
            if (participant !== user) {
                const participantWs = this.userConnections.get(participant);
                if (participantWs) {
                    this.send(participantWs, {
                        type: 'ice_candidate',
                        callId,
                        candidate,
                        from: user,
                        timestamp: Date.now()
                    });
                }
            }
        });
    }

    /**
     * Handle keep-alive ping
     */
    handleKeepAlive(user, ws, message) {
        const { callId } = message;
        
        const call = this.activeCalls.get(callId);
        if (!call || !call.participants.includes(user)) {
            return;
        }

        // Update last activity
        call.lastActivity = Date.now();

        // Send keep-alive response
        this.send(ws, {
            type: 'keep_alive_ack',
            callId,
            timestamp: Date.now()
        });
    }

    /**
     * Handle call status request
     */
    handleCallStatus(user, ws, message) {
        const { callId } = message;
        
        const call = this.activeCalls.get(callId);
        if (!call || !call.participants.includes(user)) {
            return this.sendError(ws, 'INVALID_CALL', 'Call not found or not authorized');
        }

        this.send(ws, {
            type: 'call_status_response',
            callId,
            status: call.status,
            participants: call.participants,
            duration: Date.now() - call.createdAt,
            lastActivity: call.lastActivity,
            timestamp: Date.now()
        });
    }

    /**
     * Handle media control (mute/unmute)
     */
    handleMediaControl(user, ws, message) {
        const { callId, muted = true } = message;
        
        const call = this.activeCalls.get(callId);
        if (!call || !call.participants.includes(user)) {
            return this.sendError(ws, 'INVALID_CALL', 'Call not found or not authorized');
        }

        // Forward to other participants
        call.participants.forEach(participant => {
            if (participant !== user) {
                const participantWs = this.userConnections.get(participant);
                if (participantWs) {
                    this.send(participantWs, {
                        ...message,
                        from: user,
                        timestamp: Date.now()
                    });
                }
            }
        });
    }

    /**
     * End a call
     */
    endCall(callId, endedBy, reason = 'Call ended') {
        const call = this.activeCalls.get(callId);
        if (!call) return;

        // Notify all participants
        call.participants.forEach(participant => {
            const participantWs = this.userConnections.get(participant);
            if (participantWs) {
                this.send(participantWs, {
                    type: 'call_ended',
                    callId,
                    endedBy: typeof endedBy === 'string' ? endedBy : participant,
                    reason,
                    duration: Date.now() - call.createdAt,
                    timestamp: Date.now()
                });
            }
        });

        // Clean up
        this.cleanupCall(callId, endedBy, reason);
    }

    /**
     * Clean up call resources
     */
    cleanupCall(callId, endedBy, reason) {
        // Stop keep-alive
        const keepAliveTimer = this.keepAliveTimers.get(callId);
        if (keepAliveTimer) {
            clearInterval(keepAliveTimer);
            this.keepAliveTimers.delete(callId);
        }

        // Remove from active calls
        this.activeCalls.delete(callId);

        // Emit event
        this.emit('call_ended', {
            callId,
            endedBy,
            reason,
            timestamp: Date.now()
        });
    }

    /**
     * Start keep-alive for a call
     */
    startKeepAlive(callId) {
        const timer = setInterval(() => {
            const call = this.activeCalls.get(callId);
            if (!call) {
                clearInterval(timer);
                this.keepAliveTimers.delete(callId);
                return;
            }

            // Check if call is inactive
            if (Date.now() - call.lastActivity > this.config.sessionTimeout) {
                this.endCall(callId, 'system', 'Call inactive timeout');
                return;
            }

            // Send keep-alive to all participants
            call.participants.forEach(participant => {
                const participantWs = this.userConnections.get(participant);
                if (participantWs) {
                    this.send(participantWs, {
                        type: 'keep_alive',
                        callId,
                        timestamp: Date.now()
                    });
                }
            });
        }, this.config.keepAliveInterval);

        this.keepAliveTimers.set(callId, timer);
    }

    /**
     * Handle user disconnection
     */
    handleDisconnection(user) {
        // Remove user connection
        this.userConnections.delete(user);

        // End all calls this user is participating in
        for (const [callId, call] of this.activeCalls) {
            if (call.participants.includes(user)) {
                this.endCall(callId, 'system', 'User disconnected');
            }
        }
    }

    /**
     * Send message to WebSocket
     */
    send(ws, data) {
        if (ws.readyState === 1) { // OPEN
            try {
                ws.send(JSON.stringify(data));
                return true;
            } catch (error) {
                console.error('DCP send error:', error);
                return false;
            }
        }
        return false;
    }

    /**
     * Send error message
     */
    sendError(ws, code, message) {
        return this.send(ws, {
            type: 'dcp_error',
            error: {
                code,
                message
            },
            timestamp: Date.now()
        });
    }

    /**
     * Get active call information
     */
    getCallInfo(callId) {
        return this.activeCalls.get(callId);
    }

    /**
     * Get user's active calls
     */
    getUserCalls(username) {
        const calls = [];
        for (const [callId, call] of this.activeCalls) {
            if (call.participants.includes(username)) {
                calls.push({
                    id: callId,
                    ...call
                });
            }
        }
        return calls;
    }

    /**
     * Check if user is in a call
     */
    isUserInCall(username) {
        for (const call of this.activeCalls.values()) {
            if (call.participants.includes(username)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Cleanup method for server shutdown
     */
    cleanup() {
        // End all active calls
        for (const callId of this.activeCalls.keys()) {
            this.endCall(callId, 'system', 'Server shutting down');
        }

        // Clear all timers
        for (const timer of this.keepAliveTimers.values()) {
            clearInterval(timer);
        }
        
        this.keepAliveTimers.clear();
        this.activeCalls.clear();
        this.userConnections.clear();
    }
}
