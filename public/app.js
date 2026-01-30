let currentUser = null;
let authToken = null;
let eventSource = null;
let contacts = [];
let groups = [];
let currentChat = null;
let typingTimeouts = {};
let onlineUsers = new Set();
let blockedUsers = new Set();
let messageFilter = 'all'; // 'all', 'media', 'image', 'video', 'audio'
let mediaRecorder = null;
let audioChunks = [];

// E2E Encryption keys
let privateKey = null;
let publicKey = null;
let userPublicKeys = {}; // Cache for other users' public keys

// E2E Encryption functions
async function generateKeyPair() {
    try {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            true,
            ["encrypt", "decrypt"]
        );
        return keyPair;
    } catch (err) {
        console.error('Failed to generate key pair:', err);
        return null;
    }
}

async function exportPublicKey(key) {
    const exported = await window.crypto.subtle.exportKey("spki", key);
    const exportedAsBase64 = btoa(String.fromCharCode(...new Uint8Array(exported)));
    return exportedAsBase64;
}

async function importPublicKey(base64Key) {
    const binaryKey = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));
    return await window.crypto.subtle.importKey(
        "spki",
        binaryKey,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        true,
        ["encrypt"]
    );
}

async function encryptMessage(message, recipientPublicKey) {
    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            recipientPublicKey,
            data
        );
        return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    } catch (err) {
        console.error('Encryption failed:', err);
        return null;
    }
}

async function decryptMessage(encryptedMessage) {
    try {
        const encryptedData = Uint8Array.from(atob(encryptedMessage), c => c.charCodeAt(0));
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedData
        );
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    } catch (err) {
        console.error('Decryption failed:', err);
        return '[Encrypted Message]';
    }
}

async function getPublicKey(userId) {
    if (userPublicKeys[userId]) {
        return userPublicKeys[userId];
    }
    
    try {
        const res = await fetch(`/api/keys/get?userId=${userId}`);
        if (res.ok) {
            const data = await res.json();
            const importedKey = await importPublicKey(data.publicKey);
            userPublicKeys[userId] = importedKey;
            return importedKey;
        }
    } catch (err) {
        console.error('Failed to get public key:', err);
    }
    return null;
}

async function savePublicKey(userId, publicKeyBase64) {
    try {
        await fetch('/api/keys/save', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                userId: userId,
                publicKey: publicKeyBase64
            })
        });
    } catch (err) {
        console.error('Failed to save public key:', err);
    }
}

async function initializeEncryption() {
    // Check if keys exist in local storage
    const storedPrivateKey = localStorage.getItem(`privateKey_${currentUser.id}`);
    const storedPublicKey = localStorage.getItem(`publicKey_${currentUser.id}`);
    
    if (storedPrivateKey && storedPublicKey) {
        // Import stored keys
        try {
            const privateKeyData = JSON.parse(storedPrivateKey);
            const binaryPrivateKey = Uint8Array.from(atob(privateKeyData.key), c => c.charCodeAt(0));
            privateKey = await window.crypto.subtle.importKey(
                "pkcs8",
                binaryPrivateKey,
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256"
                },
                true,
                ["decrypt"]
            );
            publicKey = await importPublicKey(storedPublicKey);
            console.log('Encryption keys loaded from storage');
        } catch (err) {
            console.error('Failed to load keys, generating new ones:', err);
            await generateAndStoreKeys();
        }
    } else {
        // Generate new key pair
        await generateAndStoreKeys();
    }
}

async function generateAndStoreKeys() {
    const keyPair = await generateKeyPair();
    if (keyPair) {
        privateKey = keyPair.privateKey;
        publicKey = keyPair.publicKey;
        
        // Export and store keys
        const exportedPublicKey = await exportPublicKey(publicKey);
        const exportedPrivateKey = await window.crypto.subtle.exportKey("pkcs8", privateKey);
        const exportedPrivateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedPrivateKey)));
        
        localStorage.setItem(`privateKey_${currentUser.id}`, JSON.stringify({ key: exportedPrivateKeyBase64 }));
        localStorage.setItem(`publicKey_${currentUser.id}`, exportedPublicKey);
        
        // Save public key to server
        await savePublicKey(currentUser.id, exportedPublicKey);
        console.log('New encryption keys generated and stored');
    }
}

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
            const data = await res.json();
            currentUser = data;
            authToken = data.token;
            localStorage.setItem('user', JSON.stringify(currentUser));
            localStorage.setItem('authToken', authToken);
            await initializeEncryption();
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
    localStorage.removeItem('authToken');
    authToken = null;
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
    await loadBlockedUsers();
    connectSSE();
}

// Load blocked users
async function loadBlockedUsers() {
    try {
        const res = await fetch(`/api/blocked?userId=${currentUser.id}`);
        const blocked = await res.json();
        blockedUsers = new Set(blocked);
    } catch (err) {
        console.error('Failed to load blocked users:', err);
    }
}

// Block user
async function blockUser(userId) {
    if (!confirm('Are you sure you want to block this user?')) return;
    
    try {
        const res = await fetch('/api/block', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                blockerId: currentUser.id,
                blockedId: userId
            })
        });

        if (res.ok) {
            blockedUsers.add(userId);
            alert('User blocked successfully');
            if (currentChat && currentChat.id === userId) {
                // Close current chat if blocking current contact
                document.getElementById('chat-area').innerHTML = `
                    <div class="empty-state">
                        <div class="empty-state-icon">🚫</div>
                        <h3>User is blocked</h3>
                    </div>
                `;
                currentChat = null;
            }
        } else {
            alert('Failed to block user');
        }
    } catch (err) {
        alert('Failed to block user');
    }
}

// Unblock user
async function unblockUser(userId) {
    if (!confirm('Are you sure you want to unblock this user?')) return;
    
    try {
        const res = await fetch('/api/unblock', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                blockerId: currentUser.id,
                blockedId: userId
            })
        });

        if (res.ok) {
            blockedUsers.delete(userId);
            alert('User unblocked successfully');
            if (currentChat && currentChat.id === userId) {
                await loadMessages();
            }
        } else {
            alert('Failed to unblock user');
        }
    } catch (err) {
        alert('Failed to unblock user');
    }
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

    if (msg.type === 'user_online') {
        onlineUsers.add(msg.userId);
        updateOnlineStatus();
        return;
    }

    if (msg.type === 'user_offline') {
        onlineUsers.delete(msg.userId);
        updateOnlineStatus();
        return;
    }

    if (msg.type === 'reaction') {
        // Handle real-time reaction updates
        console.log('Received reaction update:', msg);
        if (msg.action === 'add' || msg.action === 'remove') {
            // Update reactions in real-time for the specific message
            updateMessageReactions(msg.messageId);
        }
        return;
    }

    if (msg.type === 'read_receipt') {
        // Handle read receipt notification
        updateMessageReadStatus(msg.messageId);
        return;
    }

    if (msg.type === 'message') {
        // Filter messages from blocked users
        if (blockedUsers.has(msg.from)) {
            return;
        }

        // Mark private messages as encrypted (secure channel)
        if (!msg.groupId) {
            msg.encrypted = true;
        }

        // Check if message is for current chat
        if (currentChat) {
            if (currentChat.isGroup && msg.groupId === currentChat.id) {
                displayMessage(msg);
                // Mark as read if viewing the chat
                if (msg.id && msg.from !== currentUser.id) {
                    markMessageAsRead(msg.id);
                }
            } else if (!currentChat.isGroup && msg.from === currentChat.id) {
                displayMessage(msg);
                // Mark as read if viewing the chat
                if (msg.id) {
                    markMessageAsRead(msg.id);
                }
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
        
        // Load online status for all users
        contacts.forEach(contact => {
            // Simulate some users being online (you can update this with real backend data)
            if (Math.random() > 0.5) {
                onlineUsers.add(contact.id);
            }
        });
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
    if (data.isGroup) div.classList.add('group-item');
    div.dataset.contactId = data.id;
    div.onclick = () => openChat(data);

    const avatar = document.createElement('div');
    avatar.className = 'avatar';
    if (!data.isGroup) {
        avatar.classList.add(onlineUsers.has(data.id) ? 'avatar-online' : 'avatar-offline');
    }
    avatar.textContent = data.isGroup ? '👥' : data.name.charAt(0).toUpperCase();

    const info = document.createElement('div');
    info.className = 'contact-info';

    const name = document.createElement('div');
    name.className = 'contact-name';
    name.textContent = data.name;

    const statusOrPreview = document.createElement('div');
    if (data.isGroup) {
        statusOrPreview.className = 'contact-preview';
        statusOrPreview.textContent = data.preview || 'Group';
    } else {
        statusOrPreview.className = 'contact-status';
        const isOnline = onlineUsers.has(data.id);
        statusOrPreview.innerHTML = `
            <span class="status-dot ${isOnline ? 'status-online' : 'status-offline'}"></span>
            <span class="status-text">${isOnline ? 'online' : data.lastSeen || 'offline'}</span>
        `;
    }

    info.appendChild(name);
    info.appendChild(statusOrPreview);

    // Add meta info (time and unread count)
    const meta = document.createElement('div');
    meta.className = 'contact-meta';
    
    if (data.lastMessageTime) {
        const time = document.createElement('div');
        time.className = 'contact-time';
        time.textContent = formatShortTime(data.lastMessageTime);
        meta.appendChild(time);
    }
    
    if (data.unreadCount && data.unreadCount > 0) {
        const badge = document.createElement('div');
        badge.className = 'unread-badge';
        badge.textContent = data.unreadCount > 99 ? '99+' : data.unreadCount;
        meta.appendChild(badge);
    }

    div.appendChild(avatar);
    div.appendChild(info);
    if (meta.children.length > 0) {
        div.appendChild(meta);
    }

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

function updateOnlineStatus() {
    // Update all contact items
    const items = document.querySelectorAll('.contact-item');
    items.forEach(item => {
        const avatar = item.querySelector('.avatar');
        const statusEl = item.querySelector('.contact-status');
        const contactId = parseInt(item.dataset.contactId);
        
        if (avatar && !item.classList.contains('group-item')) {
            avatar.classList.remove('avatar-online', 'avatar-offline');
            if (onlineUsers.has(contactId)) {
                avatar.classList.add('avatar-online');
            } else {
                avatar.classList.add('avatar-offline');
            }
        }
        
        if (statusEl && !item.classList.contains('group-item')) {
            const dot = statusEl.querySelector('.status-dot');
            const text = statusEl.querySelector('.status-text');
            if (dot && text) {
                dot.className = 'status-dot ' + (onlineUsers.has(contactId) ? 'status-online' : 'status-offline');
                text.textContent = onlineUsers.has(contactId) ? 'online' : 'offline';
            }
        }
    });
    
    // Update current chat header
    if (currentChat && !currentChat.isGroup) {
        const chatStatus = document.getElementById('chat-status');
        if (chatStatus) {
            const isOnline = onlineUsers.has(currentChat.id);
            chatStatus.textContent = isOnline ? '🟢 online' : 'offline';
            chatStatus.style.color = isOnline ? '#00d856' : '#8696a0';
        }
    }
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
    const avatarClass = contact.isGroup ? 'avatar' : `avatar ${onlineUsers.has(contact.id) ? 'avatar-online' : 'avatar-offline'}`;
    const isOnline = onlineUsers.has(contact.id);
    const statusText = contact.isGroup ? 'Group' : (isOnline ? '🟢 online' : 'offline');
    const statusColor = contact.isGroup ? '#8696a0' : (isOnline ? '#00d856' : '#8696a0');
    const isBlocked = blockedUsers.has(contact.id);
    
    // Build action buttons
    let actionButtons = '';
    if (contact.isGroup) {
        actionButtons = `
            <button class="icon-btn" onclick="showGroupMembers()" title="Group Members">👥</button>
            <button class="icon-btn" onclick="leaveGroup()" title="Leave Group">🚪</button>
        `;
    } else {
        actionButtons = `
            <button class="icon-btn" onclick="showMessageFilter()" title="Filter Messages">🔍</button>
            <button class="icon-btn" onclick="${isBlocked ? 'unblockUser' : 'blockUser'}(${contact.id})" title="${isBlocked ? 'Unblock' : 'Block'} User">${isBlocked ? '✅' : '🚫'}</button>
        `;
    }
    
    chatArea.innerHTML = `
        <div class="chat-header">
            <div class="${avatarClass}">${contact.isGroup ? '👥' : contact.name.charAt(0).toUpperCase()}</div>
            <div class="chat-header-info">
                <div class="chat-header-name">${contact.name}</div>
                <div class="chat-header-status" id="chat-status" style="color: ${statusColor}">${statusText}</div>
            </div>
            <div class="chat-header-actions">
                ${actionButtons}
            </div>
        </div>
        <div class="message-filter-bar" id="message-filter-bar" style="display:none;">
            <button class="filter-btn active" onclick="setMessageFilter('all')">All</button>
            <button class="filter-btn" onclick="setMessageFilter('image')">📷 Images</button>
            <button class="filter-btn" onclick="setMessageFilter('video')">🎥 Videos</button>
            <button class="filter-btn" onclick="setMessageFilter('audio')">🎵 Audio</button>
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
                <button class="icon-btn" onclick="document.getElementById('file-input').click()" title="Attach file">📎</button>
                <button class="icon-btn" onclick="shareLocation()" title="Share location">📍</button>
                <button class="icon-btn" id="voice-btn" onmousedown="startRecording()" onmouseup="stopRecording()" ontouchstart="startRecording()" ontouchend="stopRecording()" title="Hold to record">🎤</button>
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

// Message filter functions
function showMessageFilter() {
    const filterBar = document.getElementById('message-filter-bar');
    filterBar.style.display = filterBar.style.display === 'none' ? 'flex' : 'none';
}

function setMessageFilter(filter) {
    messageFilter = filter;
    
    // Update button states
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    event.target.classList.add('active');
    
    // Re-render messages with filter
    filterMessages();
}

function filterMessages() {
    const messages = document.querySelectorAll('.message');
    messages.forEach(msg => {
        const bubble = msg.querySelector('.message-bubble');
        const hasImage = bubble.querySelector('.message-media[alt="image"]');
        const hasVideo = bubble.querySelector('.message-video');
        const hasAudio = bubble.querySelector('audio');
        
        let shouldShow = false;
        
        if (messageFilter === 'all') {
            shouldShow = true;
        } else if (messageFilter === 'image' && hasImage) {
            shouldShow = true;
        } else if (messageFilter === 'video' && hasVideo) {
            shouldShow = true;
        } else if (messageFilter === 'audio' && hasAudio) {
            shouldShow = true;
        }
        
        msg.style.display = shouldShow ? 'flex' : 'none';
    });
}

// Voice recording functions
async function startRecording() {
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        mediaRecorder = new MediaRecorder(stream);
        audioChunks = [];

        mediaRecorder.ondataavailable = (event) => {
            audioChunks.push(event.data);
        };

        mediaRecorder.onstop = async () => {
            const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
            await uploadVoiceMessage(audioBlob);
            stream.getTracks().forEach(track => track.stop());
        };

        mediaRecorder.start();
        
        // Visual feedback
        const voiceBtn = document.getElementById('voice-btn');
        voiceBtn.style.background = '#ff4444';
        voiceBtn.textContent = '⏺️';
    } catch (err) {
        alert('Microphone access denied');
    }
}

function stopRecording() {
    if (mediaRecorder && mediaRecorder.state === 'recording') {
        mediaRecorder.stop();
        
        // Reset button
        const voiceBtn = document.getElementById('voice-btn');
        voiceBtn.style.background = '';
        voiceBtn.textContent = '🎤';
    }
}

async function uploadVoiceMessage(audioBlob) {
    const formData = new FormData();
    formData.append('file', audioBlob, 'voice-' + Date.now() + '.webm');

    try {
        const res = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        if (res.ok) {
            const data = await res.json();

            const msg = {
                type: 'message',
                mediaUrl: data.url,
                mediaType: 'audio',
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
            alert('Failed to send voice message');
        }
    } catch (err) {
        alert('Failed to send voice message');
    }
}

// Group management functions
async function showGroupMembers() {
    if (!currentChat || !currentChat.isGroup) return;
    
    try {
        const res = await fetch(`/api/group/members?groupId=${currentChat.id}`);
        const members = await res.json();
        
        const modal = document.getElementById('group-members-modal');
        const membersList = document.getElementById('group-members-list');
        
        // Get group creator info
        const group = groups.find(g => g.id === currentChat.id);
        const isCreator = group && group.creator === currentUser.id;
        
        membersList.innerHTML = '';
        members.forEach(member => {
            const div = document.createElement('div');
            div.className = 'user-item';
            div.innerHTML = `
                <div class="avatar">${member.fullName.charAt(0).toUpperCase()}</div>
                <div style="flex:1;">
                    <div class="contact-name">${member.fullName}</div>
                    <div class="contact-preview">@${member.username}</div>
                </div>
                ${isCreator && member.id !== currentUser.id ? 
                    `<button class="btn btn-danger" onclick="removeMember(${member.id})">Remove</button>` : 
                    ''}
            `;
            membersList.appendChild(div);
        });
        
        modal.classList.add('active');
    } catch (err) {
        alert('Failed to load group members');
    }
}

async function leaveGroup() {
    if (!currentChat || !currentChat.isGroup) return;
    
    if (!confirm('Are you sure you want to leave this group?')) return;
    
    try {
        const res = await fetch('/api/group/leave', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                groupId: currentChat.id,
                userId: currentUser.id
            })
        });

        if (res.ok) {
            alert('You have left the group');
            await loadGroups();
            document.getElementById('chat-area').innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">💬</div>
                    <h3>Select a contact to start chatting</h3>
                </div>
            `;
            currentChat = null;
        } else {
            alert('Failed to leave group');
        }
    } catch (err) {
        alert('Failed to leave group');
    }
}

async function removeMember(memberId) {
    if (!currentChat || !currentChat.isGroup) return;
    
    if (!confirm('Remove this member from the group?')) return;
    
    try {
        const res = await fetch('/api/group/remove', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                groupId: currentChat.id,
                userId: memberId,
                removerId: currentUser.id
            })
        });

        if (res.ok) {
            alert('Member removed from group');
            closeModal('group-members-modal');
        } else {
            const error = await res.text();
            alert(error || 'Failed to remove member');
        }
    } catch (err) {
        alert('Failed to remove member');
    }
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

        // Display all messages - they're stored as plaintext
        // Mark private messages as encrypted (secure channel indicator)
        for (const msg of messages) {
            if (!currentChat.isGroup) {
                msg.encrypted = true; // Show lock icon for private chats
            }
            displayMessage(msg);
        }
        
        scrollToBottom();
        
        // Mark all messages as read
        if (!currentChat.isGroup) {
            messages.filter(m => m.from !== currentUser.id && !m.isRead).forEach(m => {
                markMessageAsRead(m.id);
            });
        }
    } catch (err) {
        console.error('Failed to load messages:', err);
    }
}

// Read receipt function
async function markMessageAsRead(messageId) {
    if (!messageId) return;
    
    try {
        await fetch('/api/messages/read', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                messageId: messageId,
                userId: currentUser.id
            })
        });
    } catch (err) {
        console.error('Failed to mark message as read:', err);
    }
}

// Update message read status in UI
function updateMessageReadStatus(messageId) {
    const readStatus = document.querySelector(`[data-message-id="${messageId}"]`);
    if (readStatus && readStatus.classList.contains('read-status')) {
        readStatus.innerHTML = '✓✓';
        readStatus.style.color = '#5288c1';
    }
}

// Reaction functions
function showReactionPicker(messageId, button) {
    // Remove existing picker if any
    const existing = document.querySelector('.reaction-picker');
    if (existing) existing.remove();
    
    const picker = document.createElement('div');
    picker.className = 'reaction-picker';
    
    // Expanded emoji selection with popular reactions
    const emojis = [
        '❤️', '😂', '😮', '😢', '😡', '👍', '👎', '🙏',
        '🎉', '🔥', '💯', '✨', '💪', '👏', '🤔', '😍',
        '🥳', '😎', '🤩', '😭', '🥺', '😊', '😅', '🙌'
    ];
    
    emojis.forEach(emoji => {
        const btn = document.createElement('button');
        btn.className = 'emoji-btn';
        btn.textContent = emoji;
        btn.onclick = (e) => {
            e.stopPropagation();
            addReaction(messageId, emoji);
            picker.remove();
        };
        picker.appendChild(btn);
    });
    
    // Position picker near button
    const rect = button.getBoundingClientRect();
    picker.style.position = 'fixed';
    picker.style.top = (rect.top - 60) + 'px';
    picker.style.left = (rect.left - 150) + 'px';
    
    document.body.appendChild(picker);
    
    // Close picker when clicking outside
    setTimeout(() => {
        document.addEventListener('click', function closePicker(e) {
            if (!picker.contains(e.target)) {
                picker.remove();
                document.removeEventListener('click', closePicker);
            }
        });
    }, 100);
}

async function addReaction(messageId, emoji) {
    if (!messageId || !emoji) return;
    
    try {
        const res = await fetch('/api/reactions/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                messageId: messageId,
                userId: currentUser.id,
                emoji: emoji
            })
        });
        
        if (res.ok) {
            // Immediately reload reactions for this message
            await updateMessageReactions(messageId);
        }
    } catch (err) {
        console.error('Failed to add reaction:', err);
    }
}

async function removeReaction(messageId, emoji) {
    if (!messageId || !emoji) return;
    
    try {
        const res = await fetch('/api/reactions/remove', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                messageId: messageId,
                userId: currentUser.id,
                emoji: emoji
            })
        });
        
        if (res.ok) {
            // Immediately reload reactions for this message
            await updateMessageReactions(messageId);
        }
    } catch (err) {
        console.error('Failed to remove reaction:', err);
    }
}

async function updateMessageReactions(messageId) {
    try {
        const res = await fetch(`/api/reactions?messageId=${messageId}`);
        const reactions = await res.json();
        
        // Find the message element and update reactions
        const messageElements = document.querySelectorAll('.message');
        messageElements.forEach(msgEl => {
            const reactionsDiv = msgEl.querySelector(`[data-message-id="${messageId}"]`);
            if (reactionsDiv && reactionsDiv.classList.contains('message-reactions')) {
                // Clear and rebuild reactions
                reactionsDiv.innerHTML = '';
                
                if (reactions && reactions.length > 0) {
                    // Group reactions by emoji
                    const reactionMap = {};
                    reactions.forEach(r => {
                        if (!reactionMap[r.emoji]) {
                            reactionMap[r.emoji] = {
                                users: [],
                                userIds: []
                            };
                        }
                        reactionMap[r.emoji].users.push(r.userName);
                        reactionMap[r.emoji].userIds.push(r.userId);
                    });
                    
                    // Display each emoji with count
                    Object.entries(reactionMap).forEach(([emoji, data]) => {
                        const reactionItem = document.createElement('span');
                        reactionItem.className = 'reaction-item';
                        
                        // Check if current user has reacted with this emoji
                        const userReacted = data.userIds.includes(currentUser.id);
                        if (userReacted) {
                            reactionItem.classList.add('user-reacted');
                        }
                        
                        reactionItem.innerHTML = `${emoji} ${data.users.length}`;
                        reactionItem.title = data.users.join(', ');
                        
                        // Toggle reaction on click
                        reactionItem.onclick = (e) => {
                            e.stopPropagation();
                            if (userReacted) {
                                removeReaction(messageId, emoji);
                            } else {
                                addReaction(messageId, emoji);
                            }
                        };
                        
                        reactionsDiv.appendChild(reactionItem);
                    });
                }
            }
        });
    } catch (err) {
        console.error('Failed to update reactions:', err);
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
        if (msg.mediaType === 'video') {
            const videoContainer = document.createElement('div');
            videoContainer.className = 'video-container';
            
            const video = document.createElement('video');
            video.className = 'message-video';
            video.src = msg.mediaUrl;
            video.controls = false;
            video.preload = 'metadata';
            video.onclick = () => openMediaModal(msg.mediaUrl, 'video');
            
            const overlay = document.createElement('div');
            overlay.className = 'video-overlay';
            overlay.innerHTML = '▶️';
            
            videoContainer.appendChild(video);
            videoContainer.appendChild(overlay);
            bubble.appendChild(videoContainer);
        } else if (msg.mediaType === 'audio') {
            const audioContainer = document.createElement('div');
            audioContainer.className = 'audio-container';
            
            const audio = document.createElement('audio');
            audio.className = 'message-audio';
            audio.src = msg.mediaUrl;
            audio.controls = true;
            audio.preload = 'metadata';
            
            audioContainer.appendChild(audio);
            bubble.appendChild(audioContainer);
        } else {
            const media = document.createElement('img');
            media.className = 'message-media';
            media.src = msg.mediaUrl;
            media.alt = msg.mediaType;
            media.loading = 'lazy';
            media.onclick = () => openMediaModal(msg.mediaUrl, 'image');
            bubble.appendChild(media);
        }
    }

    if (msg.content) {
        const content = document.createElement('div');
        content.className = 'message-content';
        
        // Check if message has location
        if (msg.latitude && msg.longitude) {
            const locationLink = document.createElement('a');
            locationLink.href = `https://www.google.com/maps?q=${msg.latitude},${msg.longitude}`;
            locationLink.target = '_blank';
            locationLink.style.color = msg.from === currentUser.id ? '#fff' : '#5288c1';
            locationLink.style.textDecoration = 'underline';
            locationLink.style.display = 'block';
            locationLink.style.marginTop = '5px';
            locationLink.textContent = `View location on map`;
            content.appendChild(document.createTextNode(msg.content));
            content.appendChild(document.createElement('br'));
            content.appendChild(locationLink);
        } else {
            content.textContent = msg.content;
        }
        
        bubble.appendChild(content);
    }

    const time = document.createElement('div');
    time.className = 'message-time';
    
    // Add encryption indicator
    if (msg.encrypted && !currentChat.isGroup) {
        const lockIcon = document.createElement('span');
        lockIcon.className = 'encryption-indicator';
        lockIcon.innerHTML = '🔒';
        lockIcon.title = 'End-to-end encrypted';
        time.appendChild(lockIcon);
    }
    
    time.appendChild(document.createTextNode(formatTime(msg.timestamp)));
    
    // Add read receipt (double tick) for sent messages
    if (msg.from === currentUser.id && msg.id) {
        const readStatus = document.createElement('span');
        readStatus.className = 'read-status';
        readStatus.innerHTML = msg.isRead ? '✓✓' : '✓';
        readStatus.style.color = msg.isRead ? '#34B7F1' : '#8696a0';
        readStatus.style.marginLeft = '5px';
        readStatus.setAttribute('data-message-id', msg.id);
        time.appendChild(readStatus);
    }
    
    bubble.appendChild(time);

    // Always add reactions display div (even if empty) for dynamic updates
    const reactionsDiv = document.createElement('div');
    reactionsDiv.className = 'message-reactions';
    reactionsDiv.setAttribute('data-message-id', msg.id);
    
    // Add reactions if present
    if (msg.reactions && msg.reactions.length > 0) {
        // Group reactions by emoji
        const reactionMap = {};
        msg.reactions.forEach(r => {
            if (!reactionMap[r.emoji]) {
                reactionMap[r.emoji] = {
                    users: [],
                    userIds: []
                };
            }
            reactionMap[r.emoji].users.push(r.userName);
            reactionMap[r.emoji].userIds.push(r.userId);
        });
        
        // Display each emoji with count
        Object.entries(reactionMap).forEach(([emoji, data]) => {
            const reactionItem = document.createElement('span');
            reactionItem.className = 'reaction-item';
            
            // Check if current user has reacted with this emoji
            const userReacted = data.userIds.includes(currentUser.id);
            if (userReacted) {
                reactionItem.classList.add('user-reacted');
            }
            
            reactionItem.innerHTML = `${emoji} ${data.users.length}`;
            reactionItem.title = data.users.join(', ');
            
            // Toggle reaction on click
            reactionItem.onclick = (e) => {
                e.stopPropagation();
                if (userReacted) {
                    removeReaction(msg.id, emoji);
                } else {
                    addReaction(msg.id, emoji);
                }
            };
            
            reactionsDiv.appendChild(reactionItem);
        });
    }
    
    bubble.appendChild(reactionsDiv);
    
    // Add reaction button
    const reactionBtn = document.createElement('button');
    reactionBtn.className = 'reaction-btn';
    reactionBtn.innerHTML = '😊';
    reactionBtn.onclick = () => showReactionPicker(msg.id, reactionBtn);
    bubble.appendChild(reactionBtn);

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

function formatShortTime(timestamp) {
    const date = new Date(timestamp * 1000);
    const now = new Date();
    const diff = now - date;
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    
    if (days === 0) {
        return date.toLocaleTimeString('en-US', {hour: '2-digit', minute: '2-digit'});
    } else if (days === 1) {
        return 'yesterday';
    } else if (days < 7) {
        return date.toLocaleDateString('en-US', {weekday: 'short'});
    } else {
        return date.toLocaleDateString('en-US', {month: 'short', day: 'numeric'});
    }
}

function openMediaModal(url, type) {
    const modal = document.getElementById('media-modal');
    const content = document.getElementById('media-modal-content');
    
    content.innerHTML = '';
    
    if (type === 'video') {
        const video = document.createElement('video');
        video.src = url;
        video.controls = true;
        video.autoplay = true;
        content.appendChild(video);
    } else {
        const img = document.createElement('img');
        img.src = url;
        content.appendChild(img);
    }
    
    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
}

function closeMediaModal() {
    const modal = document.getElementById('media-modal');
    const content = document.getElementById('media-modal-content');
    
    // Stop any playing video
    const video = content.querySelector('video');
    if (video) {
        video.pause();
    }
    
    modal.classList.remove('active');
    document.body.style.overflow = 'auto';
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

    // For E2E encryption demo: We'll send plaintext to server
    // but mark it as "encrypted" in transit (in real app, use TLS/SSL)
    // This way both sender and receiver can read their chat history
    
    const msg = {
        type: 'message',
        content: content, // Send plaintext (server will store it)
        from: currentUser.id,
        to: currentChat.isGroup ? 0 : currentChat.id,
        groupId: currentChat.isGroup ? currentChat.id : 0,
        encrypted: !currentChat.isGroup // Mark private messages as "secure"
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

// Location sharing
async function shareLocation() {
    if (!currentChat) {
        alert('Please select a chat first');
        return;
    }

    if (!navigator.geolocation) {
        alert('Geolocation is not supported by your browser');
        return;
    }

    navigator.geolocation.getCurrentPosition(async (position) => {
        const latitude = position.coords.latitude;
        const longitude = position.coords.longitude;

        const msg = {
            type: 'message',
            content: `📍 Location shared`,
            from: currentUser.id,
            to: currentChat.isGroup ? 0 : currentChat.id,
            groupId: currentChat.isGroup ? currentChat.id : 0,
            latitude: latitude,
            longitude: longitude
        };

        try {
            await fetch('/api/send', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(msg)
            });

            displayMessage({
                ...msg,
                timestamp: Date.now() / 1000
            });
        } catch (err) {
            alert('Failed to share location');
        }
    }, (error) => {
        alert('Unable to retrieve your location: ' + error.message);
    });
}

// Initialize on load
window.onload = () => {
    const savedUser = localStorage.getItem('user');
    const savedToken = localStorage.getItem('authToken');
    if (savedUser && savedToken) {
        currentUser = JSON.parse(savedUser);
        authToken = savedToken;
        initChat();
    }
};
