'use strict';

// ─── State ──────────────────────────────────────────────────────────────────
let currentSessionId = null;
let isRecording = false;
let mediaRecorder;
let audioChunks = [];

// ─── DOM Refs ────────────────────────────────────────────────────────────────
const chatContainer = document.getElementById('chatContainer');
const chatLayout = document.getElementById('chatLayout');
const userInput = document.getElementById('userInput');
const sendBtn = document.getElementById('sendBtn');
const speechBtn = document.getElementById('speechBtn');
const attachmentBtn = document.getElementById('attachmentBtn');
const fileInput = document.getElementById('fileInput');
const historyList = document.getElementById('historyList');
const btnNewChat = document.getElementById('btnNewChat');
const chatTitleBar = document.getElementById('chatTitleBar');

// ─── Utilities ───────────────────────────────────────────────────────────────
function escapeHTML(str) {
    return String(str).replace(/[&<>'"]/g, tag => (
        {'&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'}[tag]
    ));
}

function scrollToBottom() {
    chatContainer.scrollTop = chatContainer.scrollHeight;
}

// ─── Message Rendering ───────────────────────────────────────────────────────
function appendUserMessage(text) {
    const row = document.createElement('div');
    row.className = 'msg-row user';
    const isArabic = /^[\u0600-\u06FF]/.test(text.trim());
    row.innerHTML = `<div class="bubble" dir="${isArabic ? 'rtl' : 'ltr'}" style="text-align: ${isArabic ? 'right' : 'left'};">${escapeHTML(text)}</div>`;
    chatLayout.appendChild(row);
    scrollToBottom();
}

function formatMessageContent(content) {
    if (!content) return '';
    let escaped = escapeHTML(content);
    // Format ```code ``` blocks
    escaped = escaped.replace(/```([\s\S]*?)```/g, (match, code) => {
        return `<div style="background:#0f172a; border:1px solid #334155; border-left:4px solid #6366f1; border-radius:8px; padding:12px; margin:10px 0; font-family:'JetBrains Mono',monospace; font-size:0.85rem; color:#e2e8f0; white-space:pre-wrap; overflow-x:auto;">
            <code style="font-family:'JetBrains Mono',monospace; font-size:0.85rem; color:#f8fafc;">${code.trim()}</code>
        </div>`;
    });
    // Format **bold** text
    escaped = escaped.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    // Convert remaining newlines outside html tags to <br>
    return escaped.replace(/\n/g, '<br>');
}

function appendAIMessage(htmlContent, audioUrl = null) {
    const row = document.createElement('div');
    row.className = 'msg-row ai';
    const isArabic = /^[\u0600-\u06FF]/.test((htmlContent || '').trim());
    const formattedText = formatMessageContent(htmlContent);
    const audioHtml = audioUrl
        ? `<div style="margin-top: 8px;"><audio controls src="${audioUrl}" style="width: 100%; height: 35px;"></audio></div>`
        : '';
    row.innerHTML = `
        <div class="avatar ai">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="m15 6 2 2 4-4"/><path d="M2 12h20A10 10 0 1 1 12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 4-10"/>
            </svg>
        </div>
        <div class="bubble" dir="${isArabic ? 'rtl' : 'ltr'}" style="text-align:${isArabic ? 'right' : 'left'};">
            <div>${formattedText}</div>
            ${audioHtml}
        </div>`;
    chatLayout.appendChild(row);
    scrollToBottom();
}

function showTypingIndicator() {
    const id = 'typing-' + Date.now();
    const row = document.createElement('div');
    row.className = 'msg-row ai';
    row.id = id;
    row.innerHTML = `
        <div class="avatar ai">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/><path d="M12 8v4l3 3"/>
            </svg>
        </div>
        <div class="bubble"><div class="typing"><span></span><span></span><span></span></div></div>`;
    chatLayout.appendChild(row);
    scrollToBottom();
    return id;
}

// ─── Session Management ──────────────────────────────────────────────────────
async function createNewSession(title = 'New Chat') {
    try {
        const resp = await fetch('/api/chats/new', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({title})
        });
        if (!resp.ok) throw new Error('Failed to create session');
        const data = await resp.json();
        return data.session_id;
    } catch (err) {
        console.error('Failed to create new session:', err);
        return null;
    }
}

async function loadPastChats() {
    try {
        const resp = await fetch('/api/chats');
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const sessions = await resp.json();
        renderChatHistory(sessions);
    } catch (err) {
        historyList.innerHTML = '<div class="no-chats-hint">Could not load history.</div>';
    }
}

function renderChatHistory(sessions) {
    if (!sessions || sessions.length === 0) {
        historyList.innerHTML = '<div class="no-chats-hint">No past chats yet. Start a new conversation!</div>';
        return;
    }
    historyList.innerHTML = '';
    sessions.forEach(s => {
        const item = document.createElement('div');
        item.className = 'history-item' + (s.session_id === currentSessionId ? ' active' : '');
        item.dataset.sessionId = s.session_id;
        item.innerHTML = `
            <span class="history-item-title" title="${escapeHTML(s.title)}">${escapeHTML(s.title)}</span>
            <button class="history-delete-btn" data-id="${s.session_id}" title="Delete chat">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
                    <path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/>
                </svg>
            </button>`;

        item.addEventListener('click', (e) => {
            if (e.target.closest('.history-delete-btn')) return;
            loadChatSession(s.session_id, s.title);
        });

        item.querySelector('.history-delete-btn').addEventListener('click', async (e) => {
            e.stopPropagation();
            await deleteChatSession(s.session_id);
        });

        historyList.appendChild(item);
    });
}

async function loadChatSession(sessionId, title) {
    try {
        const resp = await fetch(`/api/chats/${sessionId}`);
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const data = await resp.json();

        currentSessionId = sessionId;
        chatTitleBar.textContent = title || data.title || 'Chat';

        // Clear and render messages
        chatLayout.innerHTML = '';
        if (data.messages && data.messages.length > 0) {
            data.messages.forEach(msg => {
                if (msg.role === 'user') appendUserMessage(msg.content);
                else appendAIMessage(msg.content);
            });
        } else {
            chatLayout.innerHTML = '<div class="msg-row ai"><div class="avatar ai"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg></div><div class="bubble"><p>No messages in this session yet.</p></div></div>';
        }

        // Update active state in sidebar
        document.querySelectorAll('.history-item').forEach(el => {
            el.classList.toggle('active', el.dataset.sessionId === sessionId);
        });
    } catch (err) {
        console.error('Failed to load chat session:', err);
    }
}

async function deleteChatSession(sessionId) {
    if (!confirm('Delete this chat session?')) return;
    try {
        const resp = await fetch(`/api/chats/${sessionId}`, {method: 'DELETE'});
        if (!resp.ok) throw new Error('HTTP ' + resp.status);

        // If deleted session was active, reset to new chat state
        if (currentSessionId === sessionId) {
            await startNewChat(false);
        }
        await loadPastChats();
    } catch (err) {
        console.error('Failed to delete session:', err);
    }
}

async function startNewChat(createSession = true) {
    chatLayout.innerHTML = `
        <div class="msg-row ai">
            <div class="avatar ai">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l1.4 4.6L18 8l-4.6 1.4L12 14l-1.4-4.6L6 8l4.6-1.4L12 2z"/></svg>
            </div>
            <div class="bubble">
                <p>New conversation started. How can I assist your security operations today?</p>
            </div>
        </div>`;

    if (createSession) {
        const sessionId = await createNewSession('New Chat');
        currentSessionId = sessionId;
        chatTitleBar.textContent = 'New Chat';
        await loadPastChats();
    } else {
        currentSessionId = null;
        chatTitleBar.textContent = 'Sentinel AI';
    }

    // Deactivate in sidebar
    document.querySelectorAll('.history-item').forEach(el => el.classList.remove('active'));
    userInput.focus();
}

// ─── Send Message ────────────────────────────────────────────────────────────
userInput.addEventListener('input', function () {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 200) + 'px';
    sendBtn.disabled = this.value.trim() === '' || userInput.disabled;
});

userInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        if (!sendBtn.disabled) sendMessage();
    }
});

sendBtn.addEventListener('click', sendMessage);

async function sendMessage() {
    const text = userInput.value.trim();
    if (!text || userInput.disabled) return;

    // Auto-create session if needed
    if (!currentSessionId) {
        const sessionId = await createNewSession(text.substring(0, 60));
        currentSessionId = sessionId;
        chatTitleBar.textContent = text.substring(0, 60) + (text.length > 60 ? '...' : '');
        await loadPastChats();
    }

    appendUserMessage(text);
    userInput.value = '';
    userInput.style.height = 'auto';
    userInput.disabled = true;
    sendBtn.disabled = true;

    const typingId = showTypingIndicator();

    try {
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                message: text,
                session_id: currentSessionId
            })
        });

        const typingEl = document.getElementById(typingId);
        if (typingEl) typingEl.remove();

        if (!response.ok) throw new Error('Failed to fetch response');
        const data = await response.json();
        appendAIMessage(data.response || data.reply);

        // Refresh sidebar to update title
        await loadPastChats();
    } catch (error) {
        const typingEl = document.getElementById(typingId);
        if (typingEl) typingEl.remove();
        appendAIMessage('Error connecting to AI service. Please try again.');
    } finally {
        userInput.disabled = false;
        userInput.focus();
        sendBtn.disabled = userInput.value.trim() === '';
    }
}

// ─── Speech ──────────────────────────────────────────────────────────────────
function resetMicButton() {
    isRecording = false;
    speechBtn.classList.remove('recording');
    speechBtn.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"></path><path d="M19 10v1a7 7 0 0 1-14 0v-1"></path><line x1="12" y1="19" x2="12" y2="23"></line><line x1="8" y1="23" x2="16" y2="23"></line></svg>`;
}

speechBtn.addEventListener('click', async () => {
    if (!isRecording) {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({audio: true});
            mediaRecorder = new MediaRecorder(stream);
            audioChunks = [];
            mediaRecorder.ondataavailable = (e) => { if (e.data.size > 0) audioChunks.push(e.data); };
            mediaRecorder.onstop = async () => {
                stream.getTracks().forEach(t => t.stop());
                const audioBlob = new Blob(audioChunks, {type: 'audio/wav'});
                const formData = new FormData();
                formData.append('file', audioBlob, 'voice_input.wav');
                const typingId = showTypingIndicator();
                try {
                    const res = await fetch('/api/speech-to-text', {method: 'POST', body: formData});
                    const typingEl = document.getElementById(typingId);
                    if (typingEl) typingEl.remove();
                    const data = await res.json();
                    if (res.ok) {
                        appendUserMessage(data.user_text);
                        appendAIMessage(data.ai_text, data.audio_url);
                        if (data.audio_url) new Audio(data.audio_url).play().catch(() => {});
                    } else {
                        appendAIMessage('Error processing speech.');
                    }
                } catch (err) {
                    const typingEl = document.getElementById(typingId);
                    if (typingEl) typingEl.remove();
                    appendAIMessage('Network error during speech processing.');
                } finally {
                    resetMicButton();
                }
            };
            mediaRecorder.start();
            isRecording = true;
            speechBtn.classList.add('recording');
            speechBtn.innerHTML = `<div class="audio-wave"><span></span><span></span><span></span></div>`;
        } catch (e) {
            alert('Microphone access denied or unavailable.');
            resetMicButton();
        }
    } else {
        if (mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop();
    }
});

// ─── File Upload ─────────────────────────────────────────────────────────────
attachmentBtn.addEventListener('click', () => { fileInput.click(); });

fileInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const formData = new FormData();
    formData.append('file', file);
    formData.append('prompt', 'Analyze this file for security insights.');
    appendUserMessage(`[Uploaded File: ${file.name}]`);
    const typingId = showTypingIndicator();
    try {
        const res = await fetch('/api/upload-file', {method: 'POST', body: formData});
        const typingEl = document.getElementById(typingId);
        if (typingEl) typingEl.remove();
        const data = await res.json();
        if (res.ok) {
            appendAIMessage(data.ai_text, data.audio_url);
            if (data.audio_url) new Audio(data.audio_url).play().catch(() => {});
        } else {
            appendAIMessage('Error processing file.');
        }
    } catch (err) {
        const typingEl = document.getElementById(typingId);
        if (typingEl) typingEl.remove();
        appendAIMessage('Network error uploading file.');
    }
    fileInput.value = '';
});

// ─── Init ───────────────────────────────────────────────────────────────────
btnNewChat.addEventListener('click', () => startNewChat(true));
sendBtn.disabled = true;

// Load past chats on startup
loadPastChats();