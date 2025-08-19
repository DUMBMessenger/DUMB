document.addEventListener('DOMContentLoaded', function() {
    const socket = io();
    const username = getCookie('username');
    if (!username) { window.location.href = '/login'; return; }

    const el = {
        messages: document.getElementById('messages-container'),
        input: document.getElementById('message-input'),
        send: document.getElementById('send-button'),
        profileBtn: document.getElementById('profile-button'),
        avatarTop: document.getElementById('user-avatar'),
        replyWrap: document.getElementById('reply-preview'),
        replyUser: document.querySelector('.reply-username'),
        replyText: document.querySelector('.reply-text'),
        cancelReply: document.getElementById('cancel-reply'),
        userMenu: document.getElementById('user-menu'),
        menuAvatar: document.getElementById('menu-avatar'),
        menuUsername: document.getElementById('menu-username'),
        avatarUpload: document.getElementById('avatar-upload'),
        themeToggle: document.getElementById('theme-toggle'),
        logout: document.getElementById('logout-button'),
        status: document.getElementById('connection-status')
    };

    let currentReply = null;

    function init() {
        bindEvents();
        loadProfile();
        loadHistory();
        restoreTheme();
    }

    function bindEvents() {
        el.send.addEventListener('click', sendMessage);
        el.input.addEventListener('keypress', e => { if (e.key === 'Enter') sendMessage(); });

        // --- профиль и меню
        el.profileBtn.addEventListener('click', e => {
            e.stopPropagation();
            el.menuUsername.textContent = username;
            const rect = el.profileBtn.getBoundingClientRect();
            el.userMenu.style.top = `${rect.bottom + window.scrollY}px`;
            el.userMenu.style.right = `${window.innerWidth - rect.right}px`;
            el.userMenu.style.display = 'flex';
        });
        document.addEventListener('click', () => el.userMenu.style.display = 'none');
        el.userMenu.addEventListener('click', e => e.stopPropagation());

        // --- logout
        el.logout.addEventListener('click', () => window.location.href = '/logout');

        // --- смена темы + сохранение
        el.themeToggle.addEventListener('click', () => {
            const dark = document.body.classList.toggle('dark');
            localStorage.setItem('theme', dark ? 'dark' : 'light');
        });

        // --- reply cancel
        el.cancelReply.addEventListener('click', cancelReply);

        // --- avatar upload
        el.avatarUpload.addEventListener('change', onAvatarFile);

        // --- сокет события
        socket.on('connect', () => setStatus(true));
        socket.on('disconnect', () => setStatus(false));
        socket.on('new_message', addMessage);
        socket.on('message_history', renderHistory);
        socket.on('avatar_updated', d => updateAvatars(d.username, d.avatar));
    }

    function setStatus(ok) {
        el.status.textContent = ok ? 'Подключено' : 'Отключено';
        el.status.style.color = ok ? '#4CAF50' : '#F44336';
    }

    function onAvatarFile(e) {
        if (e.target.files.length === 0) return;
        const file = e.target.files[0];
        if (file.size > 2 * 1024 * 1024) { alert('Максимум 2MB'); return; }
        const reader = new FileReader();
        reader.onload = ev => {
            socket.emit('update_avatar', ev.target.result, success => {
                if (success) updateAvatars(username, ev.target.result);
                else alert('Ошибка при сохранении аватарки');
            });
        };
        reader.readAsDataURL(file);
    }

    function updateAvatars(u, url) {
        if (u === username) { 
            el.avatarTop.src = url; 
            el.menuAvatar.src = url; 
        }
        document.querySelectorAll(`.message-avatar[data-username="${u}"]`).forEach(i => i.src = url);
    }

    function setReply(id, uname, text) {
        currentReply = id;
        el.replyUser.textContent = uname + ': ';
        el.replyText.textContent = text.length > 50 ? text.slice(0, 50) + '...' : text;
        el.replyWrap.style.display = 'flex';
        el.input.focus();
    }

    function cancelReply() {
        currentReply = null;
        el.replyWrap.style.display = 'none';
    }

    function sanitizeText(t) {
        const d = document.createElement('div');
        d.textContent = t;
        return d.textContent;
    }

    function buildMessageNode(m) {
        const isSelf = m.username === username;
        const root = document.createElement('div');
        root.className = `message ${isSelf ? 'sent' : 'received'}`;
        root.dataset.id = m.id;

        if (m.replyTo) {
            const ref = findMessageNode(m.replyTo);
            if (ref) {
                const wrap = document.createElement('div');
                wrap.className = 'message-reply';
                wrap.addEventListener('click', () => scrollToMessage(m.replyTo));
                const ru = document.createElement('span');
                ru.className = 'reply-username';
                ru.textContent = ref.querySelector('.message-username').textContent + ': ';
                const rt = document.createElement('span');
                rt.className = 'reply-text';
                rt.textContent = ref.querySelector('.message-text').textContent;
                wrap.appendChild(ru);
                wrap.appendChild(rt);
                root.appendChild(wrap);
            }
        }

        const header = document.createElement('div');
        header.className = 'message-header';
        const img = document.createElement('img');
        img.className = 'message-avatar';
        img.dataset.username = m.username;
        img.src = '/_get_avatar?username=' + encodeURIComponent(m.username);
        const uname = document.createElement('span');
        uname.className = 'message-username';
        uname.textContent = m.username;
        const time = document.createElement('span');
        time.className = 'message-time';
        time.textContent = m.timestamp;
        header.appendChild(img);
        header.appendChild(uname);
        header.appendChild(time);

        const body = document.createElement('div');
        body.className = 'message-text';
        body.textContent = sanitizeText(m.text);

        root.appendChild(header);
        root.appendChild(body);

        // --- reply: dblclick (ПК) или tap (мобила)
        root.addEventListener('dblclick', () => setReply(m.id, m.username, m.text));
        root.addEventListener('touchend', () => setReply(m.id, m.username, m.text));

        return root;
    }

    function findMessageNode(id) {
        return document.querySelector(`.message[data-id="${id}"]`);
    }

    function scrollToMessage(id) {
        const n = findMessageNode(id);
        if (!n) return;
        n.classList.add('highlight');
        setTimeout(() => n.classList.remove('highlight'), 2000);
        n.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    function addMessage(m) {
        const node = buildMessageNode(m);
        el.messages.appendChild(node);
        scrollToBottom();
    }

    function loadHistory() {
        socket.emit('get_history');
    }

    function renderHistory(list) {
        el.messages.innerHTML = '';
        list.reverse().forEach(m => el.messages.appendChild(buildMessageNode(m)));
        scrollToBottom();
    }

    function loadProfile() {
        const url = '/_get_avatar?username=' + encodeURIComponent(username);
        el.avatarTop.src = url;
        el.menuAvatar.src = url;

        socket.emit('get_profile', username, () => {
            el.avatarTop.src = url;
            el.menuAvatar.src = url;
        });
    }

    function sendMessage() {
        const text = el.input.value.trim();
        if (!text) return;
        socket.emit('send_message', { text, replyTo: currentReply || null });
        el.input.value = '';
        cancelReply();
    }

    function scrollToBottom() {
        el.messages.scrollTop = el.messages.scrollHeight;
    }

    function restoreTheme() {
        if (localStorage.getItem('theme') === 'dark') {
            document.body.classList.add('dark');
        }
    }

    function getCookie(name) {
        const value = '; ' + document.cookie;
        const parts = value.split('; ' + name + '=');
        if (parts.length === 2) return parts.pop().split(';').shift();
    }

    init();
});
