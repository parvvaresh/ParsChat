let currentUser = null;
let eventSource = null;
let contacts = [];
let groups = [];
let currentChat = null;
let typingTimeouts = {};

// Auth functions
function toggleAuth() {
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    
    if (loginForm.style.display === 'none') {
        loginForm.style.display = 'block';
        registerForm.style.display = 'none';
    } else {
        loginForm.style.display = 'none';
        registerForm.style.display = 'block';
    }
}

async function register() {
    const username = document.getElementById('reg-username').value;
    const fullName = document.getElementById('reg-fullname').value;
    const password = document.getElementById('reg-password').value;

    if (!username || !fullName || !password) {
        alert('Please fill in all fields');
        return;
    }

    try {
        const res = await fetch('/api/register', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, fullName, password})
        });

        if (res.ok) {
            const user = await res.json();
            alert('Registration successful! Please login now');
            toggleAuth();
        } else {
            const error = await res.text();
            alert('Error: ' + error);
        }
    } catch (err) {
        alert('Connection error');
    }
}

async function login() {
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    if (!username || !password) {
        alert('Please enter username and password');
        return;
    }

    try {
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });

        if (res.ok) {
            currentUser = await res.json();
            localStorage.setItem('user', JSON.stringify(currentUser));
            initChat();
        } else {
            alert('Invalid username or password');
        }
    } catch (err) {
        alert('Connection error');
    }
}

function logout() {
    localStorage.removeItem('user');
    if (eventSource) eventSource.close();
    location.reload();
}

// Chat initialization
async function initChat() {
    document.getElementById('auth-screen').style.display = 'none';
    document.getElementById('chat-screen').style.display = 'block';
    
    document.getElementById('user-name').textContent = currentUser.fullName;
    document.getElementById('user-avatar').textContent = currentUser.fullName.charAt(0).toUpperCase();

    await loadContacts();
    await loadGroups();
    connectSSE();
}

function connectSSE() {
    eventSource = new EventSource(`/events?userId=${currentUser.id}`);

    eventSource.onopen = () => {
        console.log('SSE connected');
    };

    eventSource.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        handleIncomingMessage(msg);
    };

    eventSource.onerror = () => {
        console.log('SSE disconnected');
        setTimeout(connectSSE, 3000);
    };
}

function handleIncomingMessage(msg) {
    if (msg.type === 'typing') {
        showTypingIndicator(msg.from);
        return;
    }

    if (msg.type === 'message') {
        // Check if message is for current chat
        if (currentChat) {
            if (currentChat.isGroup && msg.groupId === currentChat.id) {
                displayMessage(msg);
            } else if (!currentChat.isGroup && msg.from === currentChat.id) {
                displayMessage(msg);
            }
        }

        // Update contact preview
        updateContactPreview(msg);
    }
}

// Load contacts and groups
async function loadContacts() {
    try {
        const res = await fetch('/api/users');
        const users = await res.json();
        contacts = users.filter(u => u.id !== currentUser.id);
    } catch (err) {
        console.error('Failed to load contacts:', err);
    }
}

async function loadGroups() {
    try {
        const res = await fetch(`/api/groups?userId=${currentUser.id}`);
        groups = await res.json();
        renderContacts();
    } catch (err) {
        console.error('Failed to load groups:', err);
    }
}

function renderContacts() {
    const list = document.getElementById('contacts-list');
    list.innerHTML = '';

    // Render groups
    groups.forEach(group => {
        const item = createContactItem({
            id: group.id,
            name: group.name,
            isGroup: true,
            preview: 'Group'
        });
        list.appendChild(item);
    });

    // Render individual contacts
    contacts.forEach(contact => {
        const item = createContactItem({
            id: contact.id,
            name: contact.fullName,
            username: contact.username,
            isGroup: false,
            preview: ''
        });
        list.appendChild(item);
    });
}

function createContactItem(data) {
    const div = document.createElement('div');
    div.className = 'contact-item';
    div.onclick = () => openChat(data);

    const avatar = document.createElement('div');
    avatar.className = 'avatar';
    avatar.textContent = data.isGroup ? 'G' : data.name.charAt(0).toUpperCase();

    const info = document.createElement('div');
    info.className = 'contact-info';

    const name = document.createElement('div');
    name.className = 'contact-name';
    name.textContent = data.name;

    const preview = document.createElement('div');
    preview.className = 'contact-preview';
    preview.textContent = data.preview;

    info.appendChild(name);
    info.appendChild(preview);

    div.appendChild(avatar);
    div.appendChild(info);

    return div;
}

function filterContacts() {
    const search = document.getElementById('search-input').value.toLowerCase();
    const items = document.querySelectorAll('.contact-item');
    
    items.forEach(item => {
        const name = item.querySelector('.contact-name').textContent.toLowerCase();
        item.style.display = name.includes(search) ? 'flex' : 'none';
    });
}

function updateContactPreview(msg) {
    // Implementation for updating last message preview
}

// Open chat
async function openChat(contact) {
    currentChat = contact;

    // Update UI
    document.querySelectorAll('.contact-item').forEach(item => {
        item.classList.remove('active');
    });
    event.currentTarget.classList.add('active');

    // Build chat area
    const chatArea = document.getElementById('chat-area');
    chatArea.innerHTML = `
        <div class="chat-header">
            <div class="avatar">${contact.isGroup ? 'G' : contact.name.charAt(0).toUpperCase()}</div>
            <div class="chat-header-info">
                <div class="chat-header-name">${contact.name}</div>
                <div class="chat-header-status" id="chat-status">${contact.isGroup ? 'Group' : 'Online'}</div>
            </div>
        </div>
        <div class="messages-container" id="messages-container">
            <div class="typing-indicator" id="typing-indicator">
                <div class="typing-dots">
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
            </div>
        </div>
        <div class="input-area">
            <div class="input-actions">
                <button class="icon-btn" onclick="document.getElementById('file-input').click()">[+]</button>
            </div>
            <input type="text" class="input-field" id="message-input" 
                   placeholder="Type a message..." 
                   onkeypress="handleKeyPress(event)"
                   oninput="handleTyping()">
            <button class="send-btn" onclick="sendMessage()">Send</button>
        </div>
    `;

    await loadMessages();
}

async function loadMessages() {
    try {
        const params = currentChat.isGroup 
            ? `groupId=${currentChat.id}&userId=${currentUser.id}`
            : `userId=${currentUser.id}&contactId=${currentChat.id}`;
        
        const res = await fetch(`/api/messages?${params}`);
        const messages = await res.json();

        const container = document.getElementById('messages-container');
        const typingIndicator = container.querySelector('#typing-indicator');
        container.innerHTML = '';
        container.appendChild(typingIndicator);

        messages.forEach(msg => displayMessage(msg));
        scrollToBottom();
    } catch (err) {
        console.error('Failed to load messages:', err);
    }
}

function displayMessage(msg) {
    const container = document.getElementById('messages-container');
    if (!container) return;

    const div = document.createElement('div');
    div.className = `message ${msg.from === currentUser.id ? 'sent' : 'received'}`;

    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';

    // Show sender name in groups
    if (currentChat && currentChat.isGroup && msg.from !== currentUser.id) {
        const sender = document.createElement('div');
        sender.className = 'message-sender';
        sender.textContent = getSenderName(msg.from);
        bubble.appendChild(sender);
    }

    if (msg.mediaUrl) {
        const media = document.createElement('img');
        media.className = 'message-media';
        media.src = msg.mediaUrl;
        media.alt = msg.mediaType;
        media.onclick = () => window.open(msg.mediaUrl, '_blank');
        bubble.appendChild(media);
    }

    if (msg.content) {
        const content = document.createElement('div');
        content.className = 'message-content';
        content.textContent = msg.content;
        bubble.appendChild(content);
    }

    const time = document.createElement('div');
    time.className = 'message-time';
    time.textContent = formatTime(msg.timestamp);
    bubble.appendChild(time);

    div.appendChild(bubble);
    
    const typingIndicator = container.querySelector('#typing-indicator');
    container.insertBefore(div, typingIndicator);
    scrollToBottom();
}

function getSenderName(userId) {
    const contact = contacts.find(c => c.id === userId);
    return contact ? contact.fullName : 'User';
}

function formatTime(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toLocaleTimeString('en-US', {hour: '2-digit', minute: '2-digit'});
}

function scrollToBottom() {
    const container = document.getElementById('messages-container');
    if (container) {
        container.scrollTop = container.scrollHeight;
    }
}

// Send message
function handleKeyPress(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
    }
}

function handleTyping() {
    if (!currentChat || currentChat.isGroup) return;

    fetch('/api/typing', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            from: currentUser.id,
            to: currentChat.id
        })
    });
}

function showTypingIndicator(fromUserId) {
    if (!currentChat || currentChat.id !== fromUserId) return;

    const indicator = document.getElementById('typing-indicator');
    if (indicator) {
        indicator.classList.add('active');

        clearTimeout(typingTimeouts[fromUserId]);
        typingTimeouts[fromUserId] = setTimeout(() => {
            indicator.classList.remove('active');
        }, 3000);
    }
}

async function sendMessage() {
    const input = document.getElementById('message-input');
    const content = input.value.trim();

    if (!content || !currentChat) return;

    const msg = {
        type: 'message',
        content: content,
        from: currentUser.id,
        to: currentChat.isGroup ? 0 : currentChat.id,
        groupId: currentChat.isGroup ? currentChat.id : 0
    };

    try {
        await fetch('/api/send', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(msg)
        });

        // Display immediately
        displayMessage({
            ...msg,
            timestamp: Date.now() / 1000
        });

        input.value = '';
    } catch (err) {
        alert('Failed to send message');
    }
}

// File upload
async function uploadFile() {
    const fileInput = document.getElementById('file-input');
    const file = fileInput.files[0];
    
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    try {
        const res = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        if (res.ok) {
            const data = await res.json();
            
            const mediaType = file.type.startsWith('image/') ? 'image' : 
                            file.type.startsWith('video/') ? 'video' : 'file';

            const msg = {
                type: 'message',
                mediaUrl: data.url,
                mediaType: mediaType,
                from: currentUser.id,
                to: currentChat.isGroup ? 0 : currentChat.id,
                groupId: currentChat.isGroup ? currentChat.id : 0
            };

            await fetch('/api/send', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(msg)
            });

            displayMessage({
                ...msg,
                timestamp: Date.now() / 1000
            });
        } else {
            alert('Failed to upload file');
        }
    } catch (err) {
        alert('Failed to upload file');
    }

    fileInput.value = '';
}

// Modals
function showNewChatModal() {
    const modal = document.getElementById('new-chat-modal');
    const usersList = document.getElementById('users-for-chat');
    
    usersList.innerHTML = '';
    contacts.forEach(contact => {
        const div = document.createElement('div');
        div.className = 'user-item';
        div.style.cursor = 'pointer';
        div.onclick = () => {
            closeModal('new-chat-modal');
            openChat({
                id: contact.id,
                name: contact.fullName,
                isGroup: false
            });
        };

        div.innerHTML = `
            <div class="avatar">${contact.fullName.charAt(0).toUpperCase()}</div>
            <div>
                <div class="contact-name">${contact.fullName}</div>
                <div class="contact-preview">@${contact.username}</div>
            </div>
        `;
        usersList.appendChild(div);
    });

    modal.classList.add('active');
}

function showNewGroupModal() {
    const modal = document.getElementById('new-group-modal');
    const usersList = document.getElementById('users-for-group');
    
    usersList.innerHTML = '';
    contacts.forEach(contact => {
        const div = document.createElement('div');
        div.className = 'user-item';
        div.innerHTML = `
            <input type="checkbox" value="${contact.id}" id="user-${contact.id}">
            <div class="avatar">${contact.fullName.charAt(0).toUpperCase()}</div>
            <label for="user-${contact.id}" style="flex:1;cursor:pointer;">
                <div class="contact-name">${contact.fullName}</div>
                <div class="contact-preview">@${contact.username}</div>
            </label>
        `;
        usersList.appendChild(div);
    });

    modal.classList.add('active');
}

async function createGroup() {
    const name = document.getElementById('group-name').value.trim();
    const checkboxes = document.querySelectorAll('#users-for-group input[type="checkbox"]:checked');
    const memberIds = Array.from(checkboxes).map(cb => parseInt(cb.value));

    if (!name) {
        alert('Please enter a group name');
        return;
    }

    if (memberIds.length === 0) {
        alert('Please select at least one member');
        return;
    }

    try {
        const res = await fetch('/api/groups', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                name: name,
                creatorId: currentUser.id,
                memberIds: memberIds
            })
        });

        if (res.ok) {
            const group = await res.json();
            alert('Group created successfully');
            closeModal('new-group-modal');
            document.getElementById('group-name').value = '';
            await loadGroups();
        } else {
            alert('Failed to create group');
        }
    } catch (err) {
        alert('Failed to create group');
    }
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
}

// Initialize on load
window.onload = () => {
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
        currentUser = JSON.parse(savedUser);
        initChat();
    }
};
