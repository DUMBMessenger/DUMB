document.addEventListener('DOMContentLoaded', function() {
    const socket = io();
    const username = getCookie('username');
    
    if (!username) {
        window.location.href = '/login';
        return;
    }

    const elements = {
        messagesContainer: document.getElementById('messages-container'),
        messageInput: document.getElementById('message-input'),
        sendButton: document.getElementById('send-button'),
        profileButton: document.getElementById('profile-button'),
        userAvatar: document.getElementById('user-avatar'),
        connectionStatus: document.getElementById('connection-status'),
        logoutButton: document.getElementById('logout-button'),
        replyPreview: document.getElementById('reply-preview'),
        replyUsername: document.querySelector('.reply-username'),
        replyText: document.querySelector('.reply-text'),
        cancelReply: document.getElementById('cancel-reply'),
        userMenu: document.getElementById('user-menu'),
        menuAvatar: document.getElementById('menu-avatar'),
        menuUsername: document.getElementById('menu-username'),
        avatarUpload: document.getElementById('avatar-upload')
    };

    function initChat() {
        setupEventListeners();
        loadUserProfile();
        loadMessageHistory();
        setupReplyHandlers();
    }

    function setupEventListeners() {
        elements.sendButton.addEventListener('click', sendMessage);
        elements.messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') sendMessage();
        });

        elements.profileButton.addEventListener('click', function(e) {
            e.stopPropagation();
            elements.menuUsername.textContent = username;
            elements.menuAvatar.src = elements.userAvatar.src;
            
            const rect = elements.profileButton.getBoundingClientRect();
            elements.userMenu.style.top = `${rect.bottom + window.scrollY}px`;
            elements.userMenu.style.right = `${window.innerWidth - rect.right}px`;
            elements.userMenu.style.display = 'flex';
        });

        document.addEventListener('click', function() {
            elements.userMenu.style.display = 'none';
        });

        elements.userMenu.addEventListener('click', function(e) {
            e.stopPropagation();
        });

        elements.logoutButton.addEventListener('click', logout);

        elements.cancelReply.addEventListener('click', cancelReply);

        elements.avatarUpload.addEventListener('change', function(e) {
            if (e.target.files.length > 0) {
                const file = e.target.files[0];
                if (file.size > 2 * 1024 * 1024) {
                    alert('Максимальный размер файла - 2MB');
                    return;
                }
                
                const reader = new FileReader();
                reader.onload = function(event) {
                    socket.emit('update_avatar', event.target.result, function(success) {
                        if (success) {
                            updateAllUserAvatars(username, event.target.result);
                        } else {
                            alert('Ошибка при сохранении аватарки');
                        }
                    });
                };
                reader.readAsDataURL(file);
            }
        });

        socket.on('connect', handleConnect);
        socket.on('disconnect', handleDisconnect);
        socket.on('new_message', addMessage);
        socket.on('message_history', renderMessageHistory);
        socket.on('avatar_updated', function(data) {
            updateAllUserAvatars(data.username, data.avatar);
        });
    }

    function updateAllUserAvatars(username, avatarUrl) {
        if (username === getCookie('username')) {
            elements.userAvatar.src = avatarUrl;
            elements.menuAvatar.src = avatarUrl;
        }
        
        document.querySelectorAll(`.message-avatar[data-username="${username}"]`).forEach(img => {
            img.src = avatarUrl;
        });
    }

    function setupReplyHandlers() {
        elements.messagesContainer.addEventListener('click', function(e) {
            const messageElement = e.target.closest('.message');
            if (messageElement) {
                const header = messageElement.querySelector('.message-header');
                if (e.target.closest('.message-header') === header) {
                    const username = messageElement.querySelector('.message-username').textContent;
                    const text = messageElement.querySelector('.message-text').textContent;
                    const messageId = messageElement.dataset.id;
                    
                    setReply(messageId, username, text);
                }
            }
        });
    }

    function setReply(messageId, username, text) {
        elements.currentReply = messageId;
        elements.replyUsername.textContent = username + ': ';
        elements.replyText.textContent = text.length > 50 ? text.substring(0, 50) + '...' : text;
        elements.replyPreview.style.display = 'flex';
        elements.messageInput.focus();
    }

    function cancelReply() {
        elements.currentReply = null;
        elements.replyPreview.style.display = 'none';
    }

    function sendMessage() {
        const messageText = elements.messageInput.value.trim();
        if (!messageText) return;

        const messageData = {
            text: messageText,
            replyTo: elements.currentReply || null
        };

        socket.emit('send_message', messageData);
        elements.messageInput.value = '';
        cancelReply();
    }

    function createMessageElement(message) {
        const isCurrentUser = message.username === username;
        const messageElement = document.createElement('div');
        messageElement.className = `message ${isCurrentUser ? 'sent' : 'received'}`;
        messageElement.dataset.id = message.id;
        
        let replyHtml = '';
        if (message.replyTo) {
            const repliedMessage = findMessageInHistory(message.replyTo);
            if (repliedMessage) {
                replyHtml = `
                    <div class="message-reply" onclick="scrollToMessage('${message.replyTo}')">
                        <span class="reply-username">${repliedMessage.username}: </span>
                        <span class="reply-text">${repliedMessage.text}</span>
                    </div>
                `;
            }
        }
        
        messageElement.innerHTML = `
            ${replyHtml}
            <div class="message-header">
                <img class="message-avatar" src="/_get_avatar?username=${encodeURIComponent(message.username)}" 
                     data-username="${message.username}">
                <span class="message-username">${message.username}</span>
                <span class="message-time">${message.timestamp}</span>
            </div>
            <div class="message-text">${message.text}</div>
        `;

        return messageElement;
    }

    function findMessageInHistory(messageId) {
        const messageElement = document.querySelector(`.message[data-id="${messageId}"]`);
        if (messageElement) {
            return {
                username: messageElement.querySelector('.message-username').textContent,
                text: messageElement.querySelector('.message-text').textContent
            };
        }
        return null;
    }

    window.scrollToMessage = function(messageId) {
        const messageElement = document.querySelector(`.message[data-id="${messageId}"]`);
        if (messageElement) {
            messageElement.classList.add('highlight');
            setTimeout(() => messageElement.classList.remove('highlight'), 2000);
            messageElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    };

    function addMessage(message) {
        const messageElement = createMessageElement(message);
        elements.messagesContainer.appendChild(messageElement);
        scrollToBottom();
    }

    function loadMessageHistory() {
        socket.emit('get_history');
    }

    function renderMessageHistory(messages) {
        elements.messagesContainer.innerHTML = '';
        messages.reverse().forEach(message => {
            elements.messagesContainer.appendChild(createMessageElement(message));
        });
        scrollToBottom();
    }

    function loadUserProfile() {
        socket.emit('get_profile', username, function(profile) {
            if (profile && profile.avatar) {
                elements.userAvatar.src = profile.avatar;
                elements.menuAvatar.src = profile.avatar;
            }
        });
    }

    window.logout = function() {
        window.location.href = '/logout';
    };

    function handleConnect() {
        elements.connectionStatus.textContent = 'Подключено';
        elements.connectionStatus.style.color = '#4CAF50';
    }

    function handleDisconnect() {
        elements.connectionStatus.textContent = 'Отключено';
        elements.connectionStatus.style.color = '#F44336';
    }

    function scrollToBottom() {
        elements.messagesContainer.scrollTop = elements.messagesContainer.scrollHeight;
    }

    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
    }

    initChat();
});
