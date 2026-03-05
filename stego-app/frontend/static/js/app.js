// Advanced Steganography App - JavaScript
// Features: Deniable Stego, Duress, SSS, PQ Encryption

// Global variables
let hideImageData = null;
let extractImageData = null;
let resultImageData = null;
let sssImages = [];
let sssReconstructImages = [];
let shareResults = [];
let authToken = localStorage.getItem('authToken');
let currentUser = null;
let allHistory = [];
let currentFilter = 'all';

const API_BASE = 'http://localhost:5000/api';

// ==================== INITIALIZATION ====================

document.addEventListener('DOMContentLoaded', function () {
    if (authToken) {
        loadUserProfile();
        showMainApp();
    } else {
        showAuthPage();
    }

    // Character counter
    const messageInput = document.getElementById('hide-message');
    const charCount = document.querySelector('.char-count');

    if (messageInput && charCount) {
        messageInput.addEventListener('input', function () {
            const maxCapacity = document.getElementById('max-capacity').textContent;
            charCount.innerHTML = `${this.value.length} characters / <span id="max-capacity">${maxCapacity}</span> max`;
        });
    }

    // Password strength
    const regPassword = document.getElementById('register-password');
    if (regPassword) {
        regPassword.addEventListener('input', checkPasswordStrength);
    }

    loadUserPreferences();

    // Check URL for tokens
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    if (token) {
        const action = urlParams.get('action');
        if (action === 'reset-password') {
            handlePasswordResetToken(token);
        } else {
            handleEmailVerificationToken(token);
        }
    }
});

// ==================== PAGE NAVIGATION ====================

function showAuthPage() {
    document.getElementById('auth-page').classList.remove('hidden');
    document.getElementById('main-app').classList.add('hidden');
}

function showMainApp() {
    document.getElementById('auth-page').classList.add('hidden');
    document.getElementById('main-app').classList.remove('hidden');
}

function showLoginForm() {
    // Remove any temporary forms
    ['forgot-password-form', 'reset-password-form', 'reset-email-sent',
        'verification-pending', 'resend-verification-box'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.remove();
        });
    document.getElementById('login-form').classList.remove('hidden');
    document.getElementById('register-form').classList.add('hidden');
}

function showRegisterForm() {
    ['forgot-password-form', 'reset-password-form', 'reset-email-sent',
        'verification-pending', 'resend-verification-box'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.remove();
        });
    document.getElementById('login-form').classList.add('hidden');
    document.getElementById('register-form').classList.remove('hidden');
}

// ==================== AUTHENTICATION ====================

function checkPasswordStrength() {
    const password = document.getElementById('register-password').value;
    const strengthDiv = document.getElementById('password-strength');
    if (!strengthDiv) return;

    let strength = 0;
    if (password.length >= 6) strength++;
    if (password.length >= 10) strength++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
    if (/\d/.test(password)) strength++;
    if (/[^a-zA-Z\d]/.test(password)) strength++;

    strengthDiv.className = 'password-strength';
    if (strength <= 2) strengthDiv.classList.add('weak');
    else if (strength <= 4) strengthDiv.classList.add('medium');
    else strengthDiv.classList.add('strong');
}

function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    if (input) input.type = input.type === 'password' ? 'text' : 'password';
}

async function register() {
    const username = document.getElementById('register-username').value;
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    const confirmPassword = document.getElementById('register-confirm-password').value;

    if (!username || !email || !password || !confirmPassword) {
        showNotification('Please fill all fields', 'error');
        return;
    }
    if (password !== confirmPassword) {
        showNotification('Passwords do not match', 'error');
        return;
    }
    if (password.length < 6) {
        showNotification('Password must be at least 6 characters', 'error');
        return;
    }

    showLoading();
    try {
        const response = await fetch(`${API_BASE}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password })
        });
        const data = await response.json();
        if (response.ok && data.success) {
            showVerificationPending(email);
            showNotification('Registration successful! Check your email to verify your account.', 'success');
        } else {
            showNotification(data.error || 'Registration failed', 'error');
        }
    } catch (error) {
        showNotification(`Network error: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

async function login() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    const rememberMe = document.getElementById('remember-me').checked;

    if (!email || !password) {
        showNotification('Please fill all fields', 'error');
        return;
    }

    showLoading();
    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await response.json();

        if (response.ok && data.success) {
            authToken = data.token;
            currentUser = data.user;
            if (rememberMe) {
                localStorage.setItem('authToken', authToken);
            } else {
                sessionStorage.setItem('authToken', authToken);
            }
            showNotification(`Welcome back ${data.user.username}!`, 'success');
            showMainApp();
            updateUIForLoggedIn();
        } else if (response.status === 403 && data.requires_verification) {
            showNotification('Please verify your email first', 'error');
            showVerificationPending(email);
        } else {
            showNotification(data.error || 'Login failed', 'error');
        }
    } catch (error) {
        showNotification(`Network error: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

function logout() {
    if (confirm('Are you sure you want to logout?')) {
        authToken = null;
        currentUser = null;
        localStorage.removeItem('authToken');
        sessionStorage.removeItem('authToken');
        showNotification('Logged out successfully', 'success');
        showAuthPage();
        resetAllForms();
    }
}

async function loadUserProfile() {
    try {
        const response = await fetch(`${API_BASE}/auth/profile`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        const data = await response.json();
        if (response.ok && data.user) {
            currentUser = data.user;
            updateUIForLoggedIn();
        } else {
            logout();
        }
    } catch (error) {
        console.error('Error loading profile:', error);
    }
}

function updateUIForLoggedIn() {
    if (currentUser) {
        const el = document.getElementById('username');
        if (el) el.textContent = currentUser.username;
    }
}

function showProfile() {
    if (!currentUser) return;
    document.getElementById('profile-details').innerHTML = `
        <div class="profile-info">
            <p><strong>👤 Username:</strong> ${currentUser.username}</p>
            <p><strong>📧 Email:</strong> ${currentUser.email}</p>
            <p><strong>📊 Total Operations:</strong> ${currentUser.total_operations || 0}</p>
            <p><strong>📅 Member Since:</strong> ${new Date(currentUser.created_at).toLocaleDateString()}</p>
        </div>
    `;
    document.getElementById('profile-modal').style.display = 'block';
}

function closeProfileModal() {
    document.getElementById('profile-modal').style.display = 'none';
}

// ==================== EMAIL VERIFICATION ====================

function showVerificationPending(email) {
    document.getElementById('login-form').classList.add('hidden');
    document.getElementById('register-form').classList.add('hidden');

    const existing = document.getElementById('verification-pending');
    if (existing) existing.remove();

    const authContainer = document.querySelector('.auth-container');
    authContainer.insertAdjacentHTML('beforeend', `
        <div id="verification-pending" class="auth-form">
            <h2>📧 Verify Your Email</h2>
            <div class="verification-message">
                <p>We've sent a verification email to:</p>
                <p><strong>${email}</strong></p>
                <p>Please check your inbox and click the verification link to activate your account.</p>
                <div class="verification-tips">
                    <p><strong>💡 Tips:</strong></p>
                    <ul>
                        <li>Check your spam/junk folder</li>
                        <li>The link expires in 24 hours</li>
                    </ul>
                </div>
            </div>
            <button class="btn btn-primary" onclick="resendVerificationEmail('${email}')">
                📨 Resend Verification Email
            </button>
            <p class="auth-switch"><a href="#" onclick="showLoginForm()">Back to Login</a></p>
        </div>
    `);
}

async function resendVerificationEmail(email) {
    showLoading();
    try {
        const response = await fetch(`${API_BASE}/auth/resend-verification`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const data = await response.json();
        if (response.ok && data.success) {
            showNotification('Verification email sent! Check your inbox.', 'success');
        } else {
            showNotification(data.error || 'Failed to resend email', 'error');
        }
    } catch (error) {
        showNotification(`Network error: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

async function handleEmailVerificationToken(token) {
    showLoading();
    try {
        const response = await fetch(`${API_BASE}/auth/verify-email`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token })
        });
        const data = await response.json();
        hideLoading();

        if (response.ok && data.success) {
            authToken = data.token;
            currentUser = data.user;
            localStorage.setItem('authToken', authToken);
            showNotification('✅ Email verified successfully! Welcome!', 'success');
            window.history.replaceState({}, document.title, window.location.pathname);
            setTimeout(() => { showMainApp(); updateUIForLoggedIn(); }, 1000);
        } else {
            showNotification(data.error || 'Email verification failed. Link may be expired.', 'error');
            window.history.replaceState({}, document.title, window.location.pathname);
            showLoginForm();
        }
    } catch (error) {
        hideLoading();
        showNotification(`Network error: ${error.message}`, 'error');
        window.history.replaceState({}, document.title, window.location.pathname);
        showLoginForm();
    }
}

// ==================== PASSWORD RESET ====================

function showForgotPasswordForm() {
    document.getElementById('login-form').classList.add('hidden');
    document.getElementById('register-form').classList.add('hidden');

    const existing = document.getElementById('forgot-password-form');
    if (existing) existing.remove();

    document.querySelector('.auth-container').insertAdjacentHTML('beforeend', `
        <div id="forgot-password-form" class="auth-form">
            <h2>🔑 Reset Password</h2>
            <p>Enter your email and we'll send you a reset link.</p>
            <div class="input-group">
                <label>📧 Email</label>
                <input type="email" id="forgot-password-email" placeholder="your@email.com" autocomplete="email">
            </div>
            <button class="btn btn-primary btn-auth" onclick="requestPasswordReset()">📨 Send Reset Link</button>
            <p class="auth-switch"><a href="#" onclick="showLoginForm()">Back to Login</a></p>
        </div>
    `);
}

async function requestPasswordReset() {
    const email = document.getElementById('forgot-password-email').value;
    if (!email) { showNotification('Please enter your email address', 'error'); return; }

    showLoading();
    try {
        const response = await fetch(`${API_BASE}/auth/forgot-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        if (response.ok) {
            showNotification('If that email exists, a reset link has been sent.', 'success');
            showResetEmailSent(email);
        } else {
            const data = await response.json();
            showNotification(data.error || 'Failed to request password reset', 'error');
        }
    } catch (error) {
        showNotification(`Network error: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

function showResetEmailSent(email) {
    const form = document.getElementById('forgot-password-form');
    if (form) form.remove();

    document.querySelector('.auth-container').insertAdjacentHTML('beforeend', `
        <div id="reset-email-sent" class="auth-form">
            <h2>📧 Check Your Email</h2>
            <div class="verification-message">
                <p>If an account exists for <strong>${email}</strong>, you'll receive a password reset link shortly.</p>
                <div class="verification-tips">
                    <p><strong>💡 Next Steps:</strong></p>
                    <ul>
                        <li>Check your email inbox and spam folder</li>
                        <li>Click the reset link (expires in 1 hour)</li>
                    </ul>
                </div>
            </div>
            <p class="auth-switch"><a href="#" onclick="showLoginForm()">Back to Login</a></p>
        </div>
    `);
}

async function handlePasswordResetToken(token) {
    showLoading();
    try {
        const response = await fetch(`${API_BASE}/auth/verify-reset-token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token })
        });
        const data = await response.json();
        hideLoading();

        if (response.ok && data.valid) {
            showResetPasswordForm(token);
        } else {
            showNotification('Reset link is invalid or expired', 'error');
            window.history.replaceState({}, document.title, window.location.pathname);
            showForgotPasswordForm();
        }
    } catch (error) {
        hideLoading();
        showNotification(`Network error: ${error.message}`, 'error');
        window.history.replaceState({}, document.title, window.location.pathname);
        showLoginForm();
    }
}

function showResetPasswordForm(token) {
    document.getElementById('auth-page').classList.remove('hidden');
    document.getElementById('main-app').classList.add('hidden');
    document.getElementById('login-form').classList.add('hidden');
    document.getElementById('register-form').classList.add('hidden');

    const existing = document.getElementById('reset-password-form');
    if (existing) existing.remove();

    document.querySelector('.auth-container').insertAdjacentHTML('beforeend', `
        <div id="reset-password-form" class="auth-form">
            <h2>🔐 Create New Password</h2>
            <div class="input-group">
                <label>🔑 New Password</label>
                <input type="password" id="new-password" placeholder="Min 6 characters" autocomplete="new-password">
                <span class="toggle-password" onclick="togglePasswordVisibility('new-password')">👁️</span>
                <div class="password-strength" id="new-password-strength"></div>
            </div>
            <div class="input-group">
                <label>🔑 Confirm New Password</label>
                <input type="password" id="confirm-new-password" placeholder="Confirm new password" autocomplete="new-password">
                <span class="toggle-password" onclick="togglePasswordVisibility('confirm-new-password')">👁️</span>
            </div>
            <button class="btn btn-primary btn-auth" onclick="submitPasswordReset('${token}')">✅ Reset Password</button>
            <p class="auth-switch"><a href="#" onclick="cancelPasswordReset()">Cancel</a></p>
        </div>
    `);

    document.getElementById('new-password').addEventListener('input', function () {
        checkPasswordStrengthForInput(this.value, 'new-password-strength');
    });
}

function checkPasswordStrengthForInput(password, targetId) {
    const strengthDiv = document.getElementById(targetId);
    if (!strengthDiv) return;
    if (!password) { strengthDiv.textContent = ''; strengthDiv.className = 'password-strength'; return; }

    let strength = 0;
    if (password.length >= 6) strength++;
    if (password.length >= 10) strength++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
    if (/\d/.test(password)) strength++;
    if (/[^a-zA-Z\d]/.test(password)) strength++;

    strengthDiv.className = 'password-strength';
    if (strength <= 2) { strengthDiv.classList.add('weak'); strengthDiv.textContent = 'Weak password'; }
    else if (strength <= 4) { strengthDiv.classList.add('medium'); strengthDiv.textContent = 'Medium password'; }
    else { strengthDiv.classList.add('strong'); strengthDiv.textContent = 'Strong password'; }
}

async function submitPasswordReset(token) {
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-new-password').value;

    if (!newPassword || !confirmPassword) { showNotification('Please fill all fields', 'error'); return; }
    if (newPassword !== confirmPassword) { showNotification('Passwords do not match', 'error'); return; }
    if (newPassword.length < 6) { showNotification('Password must be at least 6 characters', 'error'); return; }

    showLoading();
    try {
        const response = await fetch(`${API_BASE}/auth/reset-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, new_password: newPassword })
        });
        const data = await response.json();

        if (response.ok && data.success) {
            showNotification('✅ Password reset successfully! You can now log in.', 'success');
            window.history.replaceState({}, document.title, window.location.pathname);
            document.getElementById('reset-password-form').remove();
            showLoginForm();
            if (data.email) document.getElementById('login-email').value = data.email;
        } else {
            showNotification(data.error || 'Password reset failed', 'error');
        }
    } catch (error) {
        showNotification(`Network error: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

function cancelPasswordReset() {
    window.history.replaceState({}, document.title, window.location.pathname);
    const form = document.getElementById('reset-password-form');
    if (form) form.remove();
    showLoginForm();
}

// ==================== SETTINGS ====================

function showSettings() {
    loadUserPreferences();
    document.getElementById('settings-modal').style.display = 'block';
}

function closeSettingsModal() {
    document.getElementById('settings-modal').style.display = 'none';
    saveUserPreferences();
}

function toggleDarkMode() {
    const isDark = document.getElementById('dark-mode').checked;
    document.body.classList.toggle('dark-mode', isDark);
}

function loadUserPreferences() {
    const prefs = JSON.parse(localStorage.getItem('userPreferences') || '{}');
    const notifEl = document.getElementById('notif-toggle');
    const autoDownloadEl = document.getElementById('auto-download');
    const compressEl = document.getElementById('compress-default');
    const clearHistoryEl = document.getElementById('clear-history-logout');

    if (notifEl && prefs.showNotifications !== undefined) notifEl.checked = !!prefs.showNotifications;
    if (autoDownloadEl && prefs.autoDownload !== undefined) autoDownloadEl.checked = !!prefs.autoDownload;
    if (compressEl && prefs.compressDefault !== undefined) compressEl.checked = !!prefs.compressDefault;
    if (clearHistoryEl && prefs.clearHistoryOnLogout !== undefined) clearHistoryEl.checked = !!prefs.clearHistoryOnLogout;
}

function saveUserPreferences() {
    const notifEl = document.getElementById('notif-toggle');
    const autoDownloadEl = document.getElementById('auto-download');
    const compressEl = document.getElementById('compress-default');
    const clearHistoryEl = document.getElementById('clear-history-logout');

    const prefs = {
        showNotifications: notifEl ? !!notifEl.checked : true,
        autoDownload: autoDownloadEl ? !!autoDownloadEl.checked : false,
        compressDefault: compressEl ? !!compressEl.checked : false,
        clearHistoryOnLogout: clearHistoryEl ? !!clearHistoryEl.checked : false
    };
    localStorage.setItem('userPreferences', JSON.stringify(prefs));
}

function changePassword() {
    showNotification('Password change will be implemented', 'info');
}

function deleteAccount() {
    // open modal for password confirmation
    const m = document.getElementById('delete-account-modal');
    if (m) { m.classList.remove('hidden'); m.style.display = 'flex'; }
}

function openDeleteAccountModal() {
    const m = document.getElementById('delete-account-modal');
    if (m) { m.classList.remove('hidden'); m.style.display = 'flex'; }
}

function populateSettings() {
    // Populate account info and preferences into the Settings panel
    if (currentUser) {
        const emailEl = document.getElementById('settings-email');
        const sinceEl = document.getElementById('settings-since');
        const typeEl = document.getElementById('settings-account-type');
        if (emailEl) emailEl.textContent = currentUser.email || '—';
        if (sinceEl) {
            try { sinceEl.textContent = new Date(currentUser.created_at).toISOString().slice(0, 10); } catch (e) { sinceEl.textContent = currentUser.created_at || '—'; }
        }
        if (typeEl) typeEl.textContent = currentUser.account_type || 'Standard';
    }
    // Load saved preferences into controls
    loadUserPreferences();
}

function saveSettings() {
    saveUserPreferences();
    showNotification('Settings saved', 'success');
}

async function submitDeleteAccount() {
    const pwdEl = document.getElementById('delete-account-password');
    const password = pwdEl ? pwdEl.value : '';
    if (!password) {
        showNotification('Please enter your password to confirm', 'error');
        return;
    }

    // Call backend delete endpoint if available
    try {
        const response = await fetch(`${API_BASE}/auth/delete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
            body: JSON.stringify({ password })
        });

        if (response.ok) {
            showNotification('Account deleted successfully', 'success');
            // Cleanup local state and show auth page
            localStorage.removeItem('authToken');
            sessionStorage.removeItem('authToken');
            authToken = null; currentUser = null;
            setTimeout(() => { showAuthPage(); }, 800);
        } else {
            const data = await response.json().catch(() => ({}));
            const err = data.error || 'Failed to delete account. Backend may not implement this.';
            showNotification(err, 'error');
        }
    } catch (err) {
        showNotification(`Error: ${err.message}`, 'error');
    } finally {
        // hide modal
        const m = document.getElementById('delete-account-modal');
        if (m) { m.classList.add('hidden'); m.style.display = 'none'; }
        if (pwdEl) pwdEl.value = '';
    }
}

// ==================== TAB SWITCHING ====================

function showTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));

    document.getElementById(`${tabName}-tab`).classList.add('active');
    event.target.classList.add('active');

    hideElement('hide-result');
    hideElement('extract-result');
    hideElement('sss-split-result');
    hideElement('sss-reconstruct-result');

    if (tabName === 'history' && authToken) {
        loadHistory();
    }
}

// ==================== ADVANCED FEATURES UI ====================

function toggleAdvancedOptions() {
    const mode = document.getElementById('stego-mode').value;
    document.getElementById('deniable-options').classList.add('hidden');
    document.getElementById('duress-options').classList.add('hidden');
    if (mode === 'deniable') document.getElementById('deniable-options').classList.remove('hidden');
    else if (mode === 'duress') document.getElementById('duress-options').classList.remove('hidden');
}

function addDecoyLayer() {
    const container = document.getElementById('decoy-container');
    const count = container.children.length + 1;
    const div = document.createElement('div');
    div.className = 'decoy-entry';
    div.innerHTML = `
        <input type="text" placeholder="Decoy message ${count}" class="decoy-message">
        <input type="password" placeholder="Decoy password ${count}" class="decoy-password">
    `;
    container.appendChild(div);
}

// ==================== IMAGE PREVIEW ====================

function previewImage(mode) {
    const input = document.getElementById(`${mode}-image`);
    const preview = document.getElementById(`${mode}-preview`);

    if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = function (e) {
            const img = document.createElement('img');
            img.src = e.target.result;
            preview.innerHTML = '';
            preview.appendChild(img);

            if (mode === 'hide') {
                hideImageData = e.target.result;
                const tempImg = new Image();
                tempImg.onload = function () {
                    const maxBytes = (this.width * this.height * 3) / 8;
                    const maxChars = Math.floor(maxBytes * 0.7);
                    document.getElementById('max-capacity').textContent = maxChars;
                    const infoDiv = document.getElementById('image-info');
                    infoDiv.innerHTML = `<strong>Image Info:</strong> ${this.width}x${this.height} pixels, Max capacity: ~${maxChars} characters`;
                    infoDiv.classList.remove('hidden');
                };
                tempImg.src = e.target.result;
            } else {
                extractImageData = e.target.result;
            }
        };
        reader.readAsDataURL(input.files[0]);
    }
}

// ==================== HIDE MESSAGE ====================

async function hideMessage() {
    const message = document.getElementById('hide-message').value;
    const password = document.getElementById('hide-password').value;
    const mode = document.getElementById('stego-mode').value;

    if (!hideImageData) { showNotification('Please select an image first', 'error'); return; }
    if (!message.trim()) { showNotification('Please enter a message to hide', 'error'); return; }
    if (!password) { showNotification('Please enter a password', 'error'); return; }

    const options = {
        mode,
        compress: document.getElementById('compress-message').checked,
        use_pq: document.getElementById('use-pq-encryption').checked
    };

    if (mode === 'deniable') {
        const decoyMessages = [];
        document.querySelectorAll('.decoy-entry').forEach(entry => {
            const msg = entry.querySelector('.decoy-message').value;
            const pass = entry.querySelector('.decoy-password').value;
            if (msg && pass) decoyMessages.push([msg, pass]);
        });
        options.decoy_messages = decoyMessages;
    }

    if (mode === 'duress') {
        options.duress_message = document.getElementById('duress-message').value || 'Nothing here';
        options.duress_password = document.getElementById('duress-password').value || 'panic123';
        options.destroy_on_duress = document.getElementById('destroy-on-duress').checked;
    }

    showLoading();
    hideElement('hide-result');

    try {
        const response = await fetch(`${API_BASE}/hide`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
            body: JSON.stringify({ image: hideImageData, message, password, options })
        });
        const data = await response.json();

        if (response.ok && data.success) {
            resultImageData = data.image;
            const outputPreview = document.getElementById('hide-output-preview');
            const img = document.createElement('img');
            img.src = data.image;
            outputPreview.innerHTML = '';
            outputPreview.appendChild(img);
            document.getElementById('hide-result-message').textContent = data.message;
            showElement('hide-result');
            showNotification('Message hidden successfully!', 'success');
            if (document.getElementById('auto-download') && document.getElementById('auto-download').checked) {
                downloadImage();
            }
        } else {
            showNotification(data.error || 'Failed to hide message', 'error');
        }
    } catch (error) {
        showNotification(`Network error: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

// ==================== EXTRACT MESSAGE ====================

async function extractMessage() {
    const password = document.getElementById('extract-password').value;
    if (!extractImageData) { showNotification('Please select an image first', 'error'); return; }
    if (!password) { showNotification('Please enter the password', 'error'); return; }

    showLoading();
    hideElement('extract-result');

    try {
        const response = await fetch(`${API_BASE}/extract`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
            body: JSON.stringify({ image: extractImageData, password })
        });
        const data = await response.json();

        if (response.ok && data.success) {
            document.getElementById('extracted-message').textContent = data.message;
            const metadata = data.metadata || {};
            let metadataHTML = `<strong>Mode:</strong> ${metadata.mode || 'standard'}`;
            if (metadata.is_duress) metadataHTML += ' <span style="color:#f59e0b;">⚠️ DURESS MODE ACTIVATED</span>';
            else if (metadata.is_decoy) metadataHTML += ' <span style="color:#f59e0b;">🎭 Decoy Layer</span>';
            else if (metadata.mode === 'deniable') metadataHTML += ' <span style="color:#48bb78;">✓ Real Layer</span>';
            document.getElementById('extract-metadata').innerHTML = metadataHTML;
            showElement('extract-result');
            showNotification('Message extracted successfully!', 'success');
        } else {
            showNotification(data.error || 'Failed to extract. Wrong password?', 'error');
        }
    } catch (error) {
        showNotification(`Network error: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

// ==================== SHAMIR SECRET SHARING ====================

// FIX: Use class-based button selection, not getElementById with wrong IDs
function showSSSMode(mode) {
    document.getElementById('sss-split').classList.add('hidden');
    document.getElementById('sss-reconstruct').classList.add('hidden');

    document.querySelectorAll('.sss-mode-btn').forEach(btn => btn.classList.remove('active'));

    if (mode === 'split') {
        document.getElementById('sss-split').classList.remove('hidden');
        document.getElementById('btn-sss-split').classList.add('active');
    } else {
        document.getElementById('sss-reconstruct').classList.remove('hidden');
        document.getElementById('btn-sss-reconstruct').classList.add('active');
    }

    hideElement('sss-split-result');
    hideElement('sss-reconstruct-result');
}

function updateSSSImageUpload() {
    const n = parseInt(document.getElementById('sss-n').value);
    const label = document.getElementById('sss-image-count-label');
    if (label) label.textContent = `(Upload ${n} images)`;
    const imagesInput = document.getElementById('sss-images');
    if (imagesInput) imagesInput.value = '';
    const preview = document.getElementById('sss-preview');
    if (preview) preview.innerHTML = '';
    const status = document.getElementById('sss-upload-status');
    if (status) status.innerHTML = '';
}

// FIX: validateSSSThreshold no longer references non-existent sss-threshold-warning element
function validateSSSThreshold() {
    const k = parseInt(document.getElementById('sss-k').value);
    const n = parseInt(document.getElementById('sss-n').value);

    if (isNaN(k) || isNaN(n) || k < 2 || n < 2) {
        showNotification('K and N must both be at least 2', 'error');
        return false;
    }
    if (k > n) {
        showNotification('Threshold K cannot be greater than N', 'error');
        return false;
    }
    return true;
}

function previewSSSImages(mode) {
    const inputId = mode === 'split' ? 'sss-images' : 'sss-reconstruct-images';
    const previewId = mode === 'split' ? 'sss-preview' : 'sss-reconstruct-preview';
    const statusId = mode === 'split' ? 'sss-upload-status' : 'sss-reconstruct-upload-status';

    const input = document.getElementById(inputId);
    const preview = document.getElementById(previewId);
    const status = document.getElementById(statusId);

    if (!input || !input.files || input.files.length === 0) {
        if (preview) preview.innerHTML = '';
        if (status) status.innerHTML = '';
        return;
    }

    const files = input.files;
    if (preview) preview.innerHTML = '';

    if (mode === 'split') {
        const n = parseInt(document.getElementById('sss-n').value);
        if (status) {
            if (files.length < n) {
                status.innerHTML = `⚠️ Uploaded ${files.length} of ${n} needed`;
                status.style.color = '#e53e3e';
            } else if (files.length > n) {
                status.innerHTML = `⚠️ Only first ${n} of ${files.length} images will be used`;
                status.style.color = '#d97706';
            } else {
                status.innerHTML = `✅ ${files.length} images ready`;
                status.style.color = '#38a169';
            }
        }
    } else {
        if (status) {
            status.innerHTML = `✅ ${files.length} share image(s) uploaded`;
            status.style.color = '#38a169';
        }
    }

    const n = mode === 'split' ? (parseInt(document.getElementById('sss-n').value) || files.length) : files.length;
    const limit = Math.min(files.length, n);

    for (let i = 0; i < limit; i++) {
        const reader = new FileReader();
        const idx = i;
        reader.onload = function (e) {
            if (!preview) return;
            const div = document.createElement('div');
            div.style.cssText = 'display:inline-block; margin:5px; text-align:center; vertical-align:top;';
            div.innerHTML = `
                <img src="${e.target.result}" style="width:80px;height:80px;object-fit:cover;border-radius:6px;border:2px solid #667eea;display:block;">
                <p style="font-size:0.8em;margin:3px 0;">${mode === 'split' ? `Carrier ${idx + 1}` : `Share ${idx + 1}`}</p>
            `;
            preview.appendChild(div);
        };
        reader.readAsDataURL(files[i]);
    }
}

async function splitSecret() {
    const secret = document.getElementById('sss-secret').value;
    const k = parseInt(document.getElementById('sss-k').value);
    const n = parseInt(document.getElementById('sss-n').value);
    const imagesInput = document.getElementById('sss-images');

    if (!secret || !secret.trim()) {
        showNotification('Please enter a secret to split', 'error');
        return;
    }
    // FIX: validateSSSThreshold no longer crashes
    if (!validateSSSThreshold()) return;

    if (!imagesInput.files || imagesInput.files.length === 0) {
        showNotification(`Please upload ${n} carrier images`, 'error');
        return;
    }
    if (imagesInput.files.length < n) {
        showNotification(`Please upload ${n} images. You only uploaded ${imagesInput.files.length}`, 'error');
        return;
    }

    showLoading();
    hideElement('sss-split-result');

    try {
        const images = [];
        for (let i = 0; i < n; i++) {
            const base64 = await fileToBase64(imagesInput.files[i]);
            images.push(base64);
        }

        const response = await fetch(`${API_BASE}/sss/split`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
            body: JSON.stringify({ secret, k, n, images })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            shareResults = data.shares;
            document.getElementById('sss-split-message').textContent = data.message;

            const sharesPreview = document.getElementById('sss-shares-preview');
            sharesPreview.innerHTML = '';

            data.shares.forEach((share, idx) => {
                // FIX: Normalize base64 prefix so images always render
                const base64Data = share.replace(/^data:image\/\w+;base64,/, '');
                const imgSrc = `data:image/png;base64,${base64Data}`;

                const div = document.createElement('div');
                div.className = 'share-item';
                div.style.cssText = 'display:inline-block; margin:8px; text-align:center; vertical-align:top;';
                div.innerHTML = `
                    <img src="${imgSrc}" alt="Share ${idx + 1}" style="width:120px;height:120px;object-fit:cover;border-radius:8px;border:2px solid #667eea;display:block;">
                    <p style="padding:6px 0;font-weight:bold;font-size:0.9em;">Share ${idx + 1} of ${n}</p>
                    <button class="btn btn-secondary" style="font-size:0.8em;padding:4px 10px;" onclick="downloadSingleShare(${idx})">
                        💾 Download
                    </button>
                `;
                sharesPreview.appendChild(div);
            });

            showElement('sss-split-result');
            showNotification('Secret split successfully!', 'success');
        } else {
            showNotification(data.error || 'Failed to split secret', 'error');
        }
    } catch (error) {
        console.error('splitSecret error:', error);
        showNotification(`Error: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

async function reconstructSecret() {
    const imagesInput = document.getElementById('sss-reconstruct-images');

    if (!imagesInput.files || imagesInput.files.length === 0) {
        showNotification('Please upload share images', 'error');
        return;
    }
    if (imagesInput.files.length < 2) {
        showNotification('Please upload at least 2 share images', 'error');
        return;
    }

    showLoading();
    hideElement('sss-reconstruct-result');

    try {
        const images = [];
        for (let i = 0; i < imagesInput.files.length; i++) {
            const base64 = await fileToBase64(imagesInput.files[i]);
            images.push(base64);
        }

        const response = await fetch(`${API_BASE}/sss/reconstruct`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
            body: JSON.stringify({ images, secret_length: 32 })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            document.getElementById('reconstructed-secret').textContent = data.secret;
            showElement('sss-reconstruct-result');
            showNotification(`Secret reconstructed from ${data.shares_used} shares!`, 'success');
        } else {
            showNotification(data.error || 'Failed to reconstruct secret', 'error');
        }
    } catch (error) {
        console.error('reconstructSecret error:', error);
        showNotification(`Error: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

function downloadAllShares() {
    if (!shareResults || shareResults.length === 0) {
        showNotification('No shares to download', 'error');
        return;
    }
    shareResults.forEach((share, idx) => {
        setTimeout(() => {
            const link = document.createElement('a');
            link.href = share;
            link.download = `share_${idx + 1}_of_${shareResults.length}.png`;
            link.click();
        }, idx * 250);
    });
    showNotification(`Downloading ${shareResults.length} shares...`, 'success');
}

function downloadSingleShare(index) {
    if (!shareResults || !shareResults[index]) {
        showNotification('Share not found', 'error');
        return;
    }
    const link = document.createElement('a');
    link.href = shareResults[index];
    link.download = `share_${index + 1}_of_${shareResults.length}.png`;
    link.click();
    showNotification(`Share ${index + 1} downloaded!`, 'success');
}

function copyReconstructedSecret() {
    const secret = document.getElementById('reconstructed-secret').textContent;
    if (!secret) { showNotification('No secret to copy', 'error'); return; }
    navigator.clipboard.writeText(secret).then(() => {
        showNotification('Secret copied to clipboard!', 'success');
    }).catch(err => {
        showNotification('Failed to copy: ' + err.message, 'error');
    });
}

// ==================== HISTORY ====================

async function loadHistory() {
    if (!authToken) {
        document.getElementById('history-content').innerHTML = '<p class="info-message">Login to see history</p>';
        return;
    }
    showLoading();
    try {
        const response = await fetch(`${API_BASE}/auth/history?limit=100`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        const data = await response.json();
        if (response.ok && data.history) {
            allHistory = data.history;
            displayHistory(allHistory);
        } else {
            document.getElementById('history-content').innerHTML = '<p class="error">Failed to load history</p>';
        }
    } catch (error) {
        document.getElementById('history-content').innerHTML = `<p class="error">Error: ${error.message}</p>`;
    } finally {
        hideLoading();
    }
}

function displayHistory(history) {
    const container = document.getElementById('history-content');
    if (history.length === 0) {
        container.innerHTML = '<p class="info-message">No history yet. Start hiding messages!</p>';
        return;
    }

    let html = '<div class="history-list">';
    history.forEach(item => {
        const date = new Date(item.created_at).toLocaleString();
        const icon = item.action.includes('hide') ? '🔒' : item.action.includes('extract') ? '🔓' : '🔀';
        const actionText = item.action.replace(/_/g, ' ').toUpperCase();
        html += `
            <div class="history-item" data-action="${item.action}">
                <div class="history-icon">${icon}</div>
                <div class="history-details">
                    <strong>${actionText}</strong>
                    ${item.message_preview ? `<p>"${item.message_preview}"</p>` : ''}
                    ${item.filename ? `<p>File: ${item.filename}</p>` : ''}
                    <small>${date}</small>
                </div>
            </div>
        `;
    });
    html += '</div>';
    container.innerHTML = html;
}

function filterHistory() {
    const searchTerm = document.getElementById('history-search').value.toLowerCase();
    let filtered = allHistory;
    if (currentFilter !== 'all') {
        filtered = filtered.filter(item => item.action.includes(currentFilter));
    }
    if (searchTerm) {
        filtered = filtered.filter(item =>
            (item.message_preview && item.message_preview.toLowerCase().includes(searchTerm)) ||
            (item.filename && item.filename.toLowerCase().includes(searchTerm))
        );
    }
    displayHistory(filtered);
}

function filterHistoryByAction(action) {
    currentFilter = action;
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    filterHistory();
}

function clearHistory() {
    if (confirm('Clear all history? This cannot be undone.')) {
        showNotification('Clear history will be implemented', 'info');
    }
}

// ==================== UTILITY FUNCTIONS ====================

function downloadImage() {
    if (!resultImageData) return;
    const link = document.createElement('a');
    link.href = resultImageData;
    link.download = `stego_${Date.now()}.png`;
    link.click();
    showNotification('Image downloaded!', 'success');
}

async function copyImageToClipboard() {
    if (!resultImageData) return;
    try {
        const blob = await (await fetch(resultImageData)).blob();
        await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
        showNotification('Image copied to clipboard!', 'success');
    } catch (error) {
        showNotification('Failed to copy image', 'error');
    }
}

function shareImage() {
    if (!resultImageData) { showNotification('No image to share', 'error'); return; }

    // Copy data URL to clipboard for easy sharing
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(resultImageData).then(() => {
            showNotification('Image URL copied to clipboard', 'success');
        }).catch(() => {
            // ignore clipboard errors
        });
    }

    // Create a small link box so user can open or download the image
    try {
        const prev = document.getElementById('share-link-box'); if (prev) prev.remove();
        const box = document.createElement('div');
        box.id = 'share-link-box';
        box.style.cssText = 'position:fixed;right:18px;top:80px;background:rgba(4,16,18,0.95);color:#bfeeee;padding:12px;border-radius:8px;border:1px solid rgba(0,200,200,0.08);z-index:10010;max-width:380px;box-shadow:0 8px 24px rgba(0,0,0,0.6);';

        const openLink = document.createElement('a');
        openLink.href = resultImageData; openLink.target = '_blank'; openLink.rel = 'noopener noreferrer';
        openLink.textContent = 'Open image in new tab'; openLink.style.cssText = 'display:block;color:#7fe0e0;margin-bottom:8px;text-decoration:none;';

        const downloadLink = document.createElement('a');
        downloadLink.href = resultImageData; downloadLink.download = `stego_${Date.now()}.png`;
        downloadLink.textContent = 'Download image'; downloadLink.style.cssText = 'display:inline-block;margin-right:12px;color:#ffb3b3;text-decoration:none;';

        const close = document.createElement('button');
        close.textContent = 'Close'; close.style.cssText = 'background:transparent;border:1px solid rgba(255,255,255,0.06);color:#dfe6ff;padding:6px 8px;border-radius:6px;cursor:pointer;';
        close.onclick = () => box.remove();

        box.appendChild(openLink); box.appendChild(downloadLink); box.appendChild(close);
        document.body.appendChild(box);
        setTimeout(() => { try { box.remove(); } catch (e) { } }, 20000);
    } catch (e) {
        showNotification('Image URL copied to clipboard', 'info');
    }
}

function copyMessage() {
    const message = document.getElementById('extracted-message').textContent;
    navigator.clipboard.writeText(message).then(() => showNotification('Message copied!', 'success'));
}

function saveAsText() {
    const message = document.getElementById('extracted-message').textContent;
    const blob = new Blob([message], { type: 'text/plain' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `extracted_message_${Date.now()}.txt`;
    link.click();
    showNotification('Message saved!', 'success');
}

function shareMessage() {
    const message = document.getElementById('extracted-message').textContent;
    if (navigator.share) {
        navigator.share({ title: 'Extracted Message', text: message });
    } else {
        showNotification('Share not supported', 'error');
    }
}

function showAbout() {
    const m = document.getElementById('about-modal');
    if (m) { m.classList.remove('hidden'); m.style.display = 'flex'; }
}

function showHelp() {
    const m = document.getElementById('help-modal');
    if (m) { m.classList.remove('hidden'); m.style.display = 'flex'; }
}

function showNotification(message, type = 'info') {
    const notifEl = document.getElementById('show-notifications');
    if (notifEl && !notifEl.checked) return;

    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed; top: 20px; right: 20px;
        padding: 15px 25px;
        background: ${type === 'success' ? '#48bb78' : type === 'error' ? '#f56565' : '#667eea'};
        color: white; border-radius: 10px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        z-index: 3000; animation: slideIn 0.3s ease-out;
        max-width: 350px; word-wrap: break-word;
    `;
    document.body.appendChild(notification);
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

function showLoading() {
    document.getElementById('loading').classList.remove('hidden');
}

function hideLoading() {
    document.getElementById('loading').classList.add('hidden');
}

function hideElement(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add('hidden');
}

function showElement(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove('hidden');
}

function resetAllForms() {
    document.querySelectorAll('input[type="file"]').forEach(input => input.value = '');
    document.querySelectorAll('input[type="password"]').forEach(input => input.value = '');
    document.querySelectorAll('textarea').forEach(textarea => textarea.value = '');
    hideImageData = null;
    extractImageData = null;
    resultImageData = null;
}

function fileToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = reject;
        reader.readAsDataURL(file);
    });
}

// CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn { from { transform: translateX(400px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    @keyframes slideOut { from { transform: translateX(0); opacity: 1; } to { transform: translateX(400px); opacity: 0; } }
    .sss-mode-btn.active { background: #667eea !important; color: white !important; }
`;
document.head.appendChild(style);

window.onclick = function (event) {
    if (event.target.classList.contains('modal')) {
        event.target.style.display = 'none';
        saveUserPreferences();
    }
};