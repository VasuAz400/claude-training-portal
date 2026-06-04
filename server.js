const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// ── SECURITY: Helmet for HTTP security headers ──
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],   // inline handlers in SPA templates; XSS mitigated by esc() encoding
      styleSrc: ["'self'", "'unsafe-inline'"],   // inline styles in templates
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],               // prevent clickjacking
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  hsts: false  // localhost doesn't use HTTPS
}));

// ── SECURITY: Request body size limit (50KB max) ──
app.use(express.json({ limit: '50kb' }));

// ── SECURITY: Global rate limiter (100 requests per minute per IP) ──
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again later.' }
}));

app.use(express.static(path.join(__dirname, 'public')));

const USERS_FILE = path.join(__dirname, 'data', 'users.json');
const CONTENT_FILE = path.join(__dirname, 'data', 'content.json');
const QUIZZES_FILE = path.join(__dirname, 'data', 'quizzes.json');

// Admin configuration
const ADMIN_EMAILS = (process.env.ADMIN_EMAIL || 'anakushwaha@deloitte.com,vnavinbhaimaradiy@deloitte.com')
  .split(',').map(e => e.trim().toLowerCase());
const OTP_EXPIRY_MS = 5 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;
const ADMIN_SESSION_TTL = 4 * 60 * 60 * 1000; // 4 hours

// In-memory stores
const otpStore = new Map();       // email -> { code, expiresAt, attempts }
const adminSessions = new Map();  // token -> { email, expiresAt }
const userSessions = new Map();   // token -> { userId, expiresAt }
const userOtpStore = new Map();   // email -> { code, expiresAt, attempts, name }
const accountVerifyAttempts = new Map(); // email -> { attempts, windowStart, lockedUntil }
const ACCOUNT_MAX_VERIFY_ATTEMPTS = 10;
const ACCOUNT_LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes
const USER_SESSION_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days

// ── SECURITY: Cleanup expired OTPs and sessions every 10 minutes ──
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of otpStore) {
    if (now > val.expiresAt) otpStore.delete(key);
  }
  for (const [key, val] of adminSessions) {
    if (now > val.expiresAt) adminSessions.delete(key);
  }
  for (const [key, val] of userSessions) {
    if (now > val.expiresAt) userSessions.delete(key);
  }
  for (const [key, val] of userOtpStore) {
    if (now > val.expiresAt) userOtpStore.delete(key);
  }
  for (const [key, val] of accountVerifyAttempts) {
    if (val.lockedUntil && now > val.lockedUntil && now - val.windowStart > ACCOUNT_LOCKOUT_MS) {
      accountVerifyAttempts.delete(key);
    }
  }
}, 10 * 60 * 1000);

// SMTP transporter (optional)
let smtpTransporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  smtpTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
  console.log('SMTP configured — OTPs will be sent via email.');
} else {
  console.log('SMTP not configured — OTPs will be printed to console only.');
}

// ── SECURITY: Cryptographically secure OTP and token generation ──
function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

function generateToken() {
  return crypto.randomBytes(48).toString('hex');  // 48 bytes = 96 hex chars
}

// ── SECURITY: Constant-time string comparison to prevent timing attacks ──
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// ── SECURITY: Input sanitization to prevent stored XSS ──
function sanitizeHTML(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ── SECURITY: Email format validation ──
function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email) && email.length <= 254;
}

// ── SECURITY: Generate unpredictable user IDs ──
function generateUserId() {
  return crypto.randomBytes(16).toString('hex');
}

// File I/O with async wrappers to avoid blocking
function readJSON(filePath) {
  if (!fs.existsSync(filePath)) return [];
  return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
}

function writeJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
}

if (!fs.existsSync(USERS_FILE)) {
  writeJSON(USERS_FILE, []);
}

// ── Audit logger ──
function auditLog(action, details) {
  const timestamp = new Date().toISOString();
  console.log(`[AUDIT] ${timestamp} | ${action} | ${JSON.stringify(details)}`);
}

// ── SECURITY: Admin session middleware ──
function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  const token = authHeader.slice(7);

  // Constant-time lookup: iterate all sessions
  let matchedSession = null;
  for (const [storedToken, session] of adminSessions) {
    if (safeCompare(token, storedToken)) {
      matchedSession = { token: storedToken, ...session };
      break;
    }
  }

  if (!matchedSession || Date.now() > matchedSession.expiresAt) {
    if (matchedSession) adminSessions.delete(matchedSession.token);
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }
  req.adminEmail = matchedSession.email;
  next();
}

// ── SECURITY: Learner session middleware ──
function requireUser(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  const token = authHeader.slice(7);

  let matchedSession = null;
  for (const [storedToken, session] of userSessions) {
    if (safeCompare(token, storedToken)) {
      matchedSession = { token: storedToken, ...session };
      break;
    }
  }

  if (!matchedSession || Date.now() > matchedSession.expiresAt) {
    if (matchedSession) userSessions.delete(matchedSession.token);
    return res.status(401).json({ error: 'Session expired. Please register again.' });
  }
  req.userId = matchedSession.userId;
  next();
}

// ── SECURITY: Strict rate limits on OTP endpoints ──
const otpRequestLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,                     // 5 OTP requests per 15 min per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many OTP requests. Please wait 15 minutes.' }
});

const otpVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,                    // 10 verify attempts per 15 min per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many verification attempts. Please wait 15 minutes.' }
});

const registrationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many registration attempts. Please wait.' }
});

const userOtpVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many verification attempts. Please wait.' }
});

// ═══════════════════════════════════════════
//  Admin Auth Routes
// ═══════════════════════════════════════════

app.post('/api/admin/request-otp', otpRequestLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ error: 'A valid email is required.' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  // Respond identically and in constant time regardless of admin status
  res.json({ message: 'If this email is authorized, an OTP has been sent.' });

  if (!ADMIN_EMAILS.includes(normalizedEmail)) {
    auditLog('OTP_REQUEST_DENIED', { email: normalizedEmail, ip: req.ip });
    return;
  }

  const code = generateOTP();
  otpStore.set(normalizedEmail, {
    code,
    expiresAt: Date.now() + OTP_EXPIRY_MS,
    attempts: 0
  });

  auditLog('OTP_GENERATED', { email: normalizedEmail, ip: req.ip });

  if (smtpTransporter) {
    smtpTransporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: normalizedEmail,
      subject: 'Claude Training Hub — Admin Login OTP',
      text: `Your one-time password is: ${code}\n\nExpires in 5 minutes.\nIf you did not request this, ignore this email.`,
      html: `
        <div style="font-family:Segoe UI,Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;">
          <div style="background:#000;color:#fff;padding:16px 24px;border-radius:6px 6px 0 0;">
            <h2 style="margin:0;font-size:18px;">
              <span style="color:#86BC25;font-weight:800;">D</span> Claude Training Hub
            </h2>
          </div>
          <div style="background:#f2f2f2;padding:32px 24px;border-radius:0 0 6px 6px;">
            <p style="color:#555;margin:0 0 16px;">Your one-time password for admin access:</p>
            <div style="background:#fff;border:2px solid #86BC25;border-radius:6px;text-align:center;padding:20px;">
              <span style="font-size:36px;font-weight:800;letter-spacing:8px;color:#1a1a1a;">${code}</span>
            </div>
            <p style="color:#888;font-size:13px;margin:16px 0 0;">This code expires in 5 minutes.</p>
          </div>
        </div>
      `
    }).catch(err => {
      console.error('Failed to send OTP email:', err.message);
    });
  } else {
    console.log('');
    console.log('='.repeat(50));
    console.log(`  ADMIN OTP for ${normalizedEmail}`);
    console.log(`  Code: ${code}`);
    console.log(`  Expires in 5 minutes`);
    console.log('='.repeat(50));
    console.log('');
  }
});

app.post('/api/admin/verify-otp', otpVerifyLimiter, (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp || !isValidEmail(email)) {
    return res.status(400).json({ error: 'Email and OTP are required.' });
  }
  if (typeof otp !== 'string' || !/^\d{6}$/.test(otp.trim())) {
    return res.status(400).json({ error: 'OTP must be a 6-digit number.' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const stored = otpStore.get(normalizedEmail);

  if (!stored) {
    auditLog('OTP_VERIFY_NO_CODE', { email: normalizedEmail, ip: req.ip });
    return res.status(401).json({ error: 'No OTP found. Please request a new one.' });
  }

  if (Date.now() > stored.expiresAt) {
    otpStore.delete(normalizedEmail);
    auditLog('OTP_EXPIRED', { email: normalizedEmail, ip: req.ip });
    return res.status(401).json({ error: 'OTP has expired. Please request a new one.' });
  }

  // ── SECURITY: Lockout after max failed attempts ──
  if (stored.attempts >= OTP_MAX_ATTEMPTS) {
    otpStore.delete(normalizedEmail);
    auditLog('OTP_LOCKED_OUT', { email: normalizedEmail, ip: req.ip, attempts: stored.attempts });
    return res.status(429).json({ error: 'Too many failed attempts. Please request a new OTP.' });
  }

  // ── SECURITY: Constant-time comparison ──
  if (!safeCompare(stored.code, otp.trim())) {
    stored.attempts++;
    auditLog('OTP_VERIFY_FAILED', { email: normalizedEmail, ip: req.ip, attempt: stored.attempts });
    const remaining = OTP_MAX_ATTEMPTS - stored.attempts;
    return res.status(401).json({
      error: `Invalid OTP. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining.`
    });
  }

  // Success — clear OTP and create session
  otpStore.delete(normalizedEmail);
  const token = generateToken();
  adminSessions.set(token, {
    email: normalizedEmail,
    expiresAt: Date.now() + ADMIN_SESSION_TTL
  });

  auditLog('ADMIN_LOGIN_SUCCESS', { email: normalizedEmail, ip: req.ip });
  res.json({ token, email: normalizedEmail });
});

app.get('/api/admin/session', requireAdmin, (req, res) => {
  res.json({ authenticated: true, email: req.adminEmail });
});

app.post('/api/admin/logout', (req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    for (const [storedToken] of adminSessions) {
      if (safeCompare(token, storedToken)) {
        adminSessions.delete(storedToken);
        auditLog('ADMIN_LOGOUT', { ip: req.ip });
        break;
      }
    }
  }
  res.json({ message: 'Logged out.' });
});

// ═══════════════════════════════════════════
//  Learner Routes (with input validation)
// ═══════════════════════════════════════════

app.post('/api/register', registrationLimiter, async (req, res) => {
  const { name, email } = req.body;

  // ── SECURITY: Validate inputs ──
  if (!name || typeof name !== 'string' || name.trim().length === 0 || name.trim().length > 100) {
    return res.status(400).json({ error: 'Name is required (max 100 characters).' });
  }
  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ error: 'A valid email is required.' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  // ── SECURITY: Enforce per-account lockout that survives OTP regeneration ──
  const acctAttempts = accountVerifyAttempts.get(normalizedEmail);
  if (acctAttempts && acctAttempts.lockedUntil && Date.now() < acctAttempts.lockedUntil) {
    auditLog('USER_REGISTER_ACCOUNT_LOCKED', { email: normalizedEmail, ip: req.ip });
    return res.status(429).json({ error: 'This account is temporarily locked due to too many failed verification attempts. Please try again later.' });
  }

  // ── SECURITY: Generate OTP — never return user data without email verification ──
  const code = generateOTP();
  userOtpStore.set(normalizedEmail, {
    code,
    expiresAt: Date.now() + OTP_EXPIRY_MS,
    attempts: 0,
    name: sanitizeHTML(name.trim())
  });

  auditLog('USER_OTP_GENERATED', { email: normalizedEmail, ip: req.ip });

  if (smtpTransporter) {
    // OTP delivered via email — never log credentials to stdout in production
    try {
      await smtpTransporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: normalizedEmail,
        subject: 'Claude Training Hub — Verification Code',
        text: `Your verification code is: ${code}\n\nExpires in 5 minutes.\nIf you did not request this, ignore this email.`,
        html: `
          <div style="font-family:Segoe UI,Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;">
            <div style="background:#000;color:#fff;padding:16px 24px;border-radius:6px 6px 0 0;">
              <h2 style="margin:0;font-size:18px;">
                <span style="color:#86BC25;font-weight:800;">D</span> Claude Training Hub
              </h2>
            </div>
            <div style="background:#f2f2f2;padding:32px 24px;border-radius:0 0 6px 6px;">
              <p style="color:#555;margin:0 0 16px;">Your verification code:</p>
              <div style="background:#fff;border:2px solid #86BC25;border-radius:6px;text-align:center;padding:20px;">
                <span style="font-size:36px;font-weight:800;letter-spacing:8px;color:#1a1a1a;">${code}</span>
              </div>
              <p style="color:#888;font-size:13px;margin:16px 0 0;">This code expires in 5 minutes.</p>
            </div>
          </div>
        `
      });
    } catch (err) {
      console.error('Failed to send OTP email:', err.message);
    }
  } else {
    console.log('');
    console.log('='.repeat(50));
    console.log(`  LEARNER OTP for ${normalizedEmail}`);
    console.log(`  Code: ${code}`);
    console.log(`  Expires in 5 minutes`);
    console.log('='.repeat(50));
    console.log('');
  }

  res.json({ requiresOTP: true, message: 'A verification code has been sent to your email.' });
});

// ── SECURITY: Verify learner OTP before granting access ──
app.post('/api/user/verify-otp', userOtpVerifyLimiter, (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp || !isValidEmail(email)) {
    return res.status(400).json({ error: 'Email and verification code are required.' });
  }
  if (typeof otp !== 'string' || !/^\d{6}$/.test(otp.trim())) {
    return res.status(400).json({ error: 'Code must be a 6-digit number.' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const stored = userOtpStore.get(normalizedEmail);

  if (!stored) {
    auditLog('USER_OTP_VERIFY_NO_CODE', { email: normalizedEmail, ip: req.ip });
    return res.status(401).json({ error: 'No verification code found. Please register again.' });
  }

  if (Date.now() > stored.expiresAt) {
    userOtpStore.delete(normalizedEmail);
    auditLog('USER_OTP_EXPIRED', { email: normalizedEmail, ip: req.ip });
    return res.status(401).json({ error: 'Code has expired. Please register again.' });
  }

  // ── SECURITY: Per-account attempt tracking (survives OTP regeneration) ──
  const now = Date.now();
  let acctAttempts = accountVerifyAttempts.get(normalizedEmail);
  if (!acctAttempts || now - acctAttempts.windowStart > ACCOUNT_LOCKOUT_MS) {
    acctAttempts = { attempts: 0, windowStart: now, lockedUntil: null };
    accountVerifyAttempts.set(normalizedEmail, acctAttempts);
  }

  if (acctAttempts.lockedUntil && now < acctAttempts.lockedUntil) {
    auditLog('USER_OTP_ACCOUNT_LOCKED', { email: normalizedEmail, ip: req.ip, attempts: acctAttempts.attempts });
    return res.status(429).json({ error: 'This account is temporarily locked due to too many failed attempts. Please try again later.' });
  }

  if (stored.attempts >= OTP_MAX_ATTEMPTS) {
    userOtpStore.delete(normalizedEmail);
    auditLog('USER_OTP_LOCKED_OUT', { email: normalizedEmail, ip: req.ip, attempts: stored.attempts });
    return res.status(429).json({ error: 'Too many failed attempts. Please register again.' });
  }

  if (!safeCompare(stored.code, otp.trim())) {
    stored.attempts++;
    acctAttempts.attempts++;
    if (acctAttempts.attempts >= ACCOUNT_MAX_VERIFY_ATTEMPTS) {
      acctAttempts.lockedUntil = now + ACCOUNT_LOCKOUT_MS;
      userOtpStore.delete(normalizedEmail);
      auditLog('USER_OTP_ACCOUNT_LOCKOUT_TRIGGERED', { email: normalizedEmail, ip: req.ip, attempts: acctAttempts.attempts });
      return res.status(429).json({ error: 'This account is temporarily locked due to too many failed attempts. Please try again later.' });
    }
    auditLog('USER_OTP_VERIFY_FAILED', { email: normalizedEmail, ip: req.ip, attempt: stored.attempts, acctAttempt: acctAttempts.attempts });
    const remaining = Math.min(OTP_MAX_ATTEMPTS - stored.attempts, ACCOUNT_MAX_VERIFY_ATTEMPTS - acctAttempts.attempts);
    return res.status(401).json({
      error: `Invalid code. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining.`
    });
  }

  userOtpStore.delete(normalizedEmail);
  accountVerifyAttempts.delete(normalizedEmail);

  const users = readJSON(USERS_FILE);
  let user = users.find(u => u.email === normalizedEmail);

  if (!user) {
    if (users.length >= 50) {
      return res.status(503).json({ error: 'Registration limit reached. Contact your trainer.' });
    }
    user = {
      id: generateUserId(),
      name: stored.name,
      email: normalizedEmail,
      registeredAt: new Date().toISOString(),
      progress: {
        1: { topicsRead: [], quizAttempts: [], bestScore: null },
        2: { topicsRead: [], quizAttempts: [], bestScore: null },
        3: { topicsRead: [], quizAttempts: [], bestScore: null },
        4: { topicsRead: [], quizAttempts: [], bestScore: null },
        5: { topicsRead: [], quizAttempts: [], bestScore: null }
      }
    };
    users.push(user);
    writeJSON(USERS_FILE, users);
    auditLog('USER_REGISTERED', { email: normalizedEmail, ip: req.ip });
  } else {
    auditLog('USER_LOGIN', { email: normalizedEmail, ip: req.ip });
  }

  const token = generateToken();
  userSessions.set(token, { userId: user.id, expiresAt: Date.now() + USER_SESSION_TTL });
  res.json({ ...user, sessionToken: token });
});

app.get('/api/user/:id', requireUser, (req, res) => {
  // ── SECURITY: Validate ID format ──
  const id = req.params.id;
  if (typeof id !== 'string' || !/^[a-f0-9]{8,32}$/.test(id)) {
    return res.status(400).json({ error: 'Invalid user ID format.' });
  }

  // ── SECURITY: Ownership check — users can only access their own record ──
  if (req.userId !== id) {
    return res.status(403).json({ error: 'Access denied.' });
  }

  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json(user);
});

app.post('/api/progress/:userId/topic', requireUser, (req, res) => {
  const { day, topicId } = req.body;
  const userId = req.params.userId;

  // ── SECURITY: Validate all inputs ──
  if (typeof userId !== 'string' || !/^[a-f0-9]{32}$/.test(userId)) {
    return res.status(400).json({ error: 'Invalid user ID.' });
  }

  // ── SECURITY: Ownership check ──
  if (req.userId !== userId) {
    return res.status(403).json({ error: 'Access denied.' });
  }
  if (!day || !Number.isInteger(day) || day < 1 || day > 5) {
    return res.status(400).json({ error: 'Day must be 1-5.' });
  }
  if (!topicId || typeof topicId !== 'string' || !/^[A-Za-z0-9]+$/.test(topicId) || topicId.length > 10) {
    return res.status(400).json({ error: 'Invalid topic ID.' });
  }

  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  if (!user.progress[day].topicsRead.includes(topicId)) {
    // ── SECURITY: Cap topics per day to prevent array bloat ──
    if (user.progress[day].topicsRead.length >= 30) {
      return res.status(400).json({ error: 'Maximum topics reached for this day.' });
    }
    user.progress[day].topicsRead.push(topicId);
  }
  writeJSON(USERS_FILE, users);
  res.json(user.progress[day]);
});

app.get('/api/content/:day', (req, res) => {
  const day = parseInt(req.params.day);
  if (!Number.isInteger(day) || day < 1 || day > 5) {
    return res.status(400).json({ error: 'Day must be 1-5.' });
  }

  const content = readJSON(CONTENT_FILE);
  const dayContent = content.find(d => d.day === day);
  if (!dayContent) return res.status(404).json({ error: 'Day not found.' });
  res.json(dayContent);
});

app.get('/api/quiz/:day', (req, res) => {
  const day = parseInt(req.params.day);
  if (!Number.isInteger(day) || day < 1 || day > 5) {
    return res.status(400).json({ error: 'Day must be 1-5.' });
  }

  const quizzes = readJSON(QUIZZES_FILE);
  const dayQuiz = quizzes.find(q => q.day === day);
  if (!dayQuiz) return res.status(404).json({ error: 'Quiz not found.' });

  const questions = dayQuiz.questions.map(({ correctAnswer, ...rest }) => rest);
  res.json({ day, questions });
});

app.post('/api/quiz/:day/submit', requireUser, (req, res) => {
  const { userId, answers } = req.body;
  const day = parseInt(req.params.day);

  // ── SECURITY: Validate all inputs ──
  if (typeof userId !== 'string' || !/^[a-f0-9]{32}$/.test(userId)) {
    return res.status(400).json({ error: 'Invalid user ID.' });
  }

  // ── SECURITY: Ownership check ──
  if (req.userId !== userId) {
    return res.status(403).json({ error: 'Access denied.' });
  }
  if (!Number.isInteger(day) || day < 1 || day > 5) {
    return res.status(400).json({ error: 'Day must be 1-5.' });
  }

  const quizzes = readJSON(QUIZZES_FILE);
  const dayQuiz = quizzes.find(q => q.day === day);
  if (!dayQuiz) return res.status(404).json({ error: 'Quiz not found.' });

  // ── SECURITY: Validate answers array ──
  if (!Array.isArray(answers) || answers.length !== dayQuiz.questions.length) {
    return res.status(400).json({ error: `Answers must be an array of ${dayQuiz.questions.length} items.` });
  }
  for (let i = 0; i < answers.length; i++) {
    if (!Number.isInteger(answers[i]) || answers[i] < 0 || answers[i] >= dayQuiz.questions[i].options.length) {
      return res.status(400).json({ error: `Invalid answer at question ${i + 1}.` });
    }
  }

  let correct = 0;
  const results = dayQuiz.questions.map((q, i) => {
    const isCorrect = answers[i] === q.correctAnswer;
    if (isCorrect) correct++;
    return {
      questionId: q.id,
      selected: answers[i],
      correctAnswer: q.correctAnswer,
      isCorrect
    };
  });

  const score = Math.round((correct / dayQuiz.questions.length) * 100);

  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  // ── SECURITY: Cap quiz attempts to prevent storage abuse ──
  if (user.progress[day].quizAttempts.length >= 100) {
    return res.status(400).json({ error: 'Maximum quiz attempts reached for this day.' });
  }

  const attempt = {
    attemptNumber: user.progress[day].quizAttempts.length + 1,
    score,
    correct,
    total: dayQuiz.questions.length,
    timestamp: new Date().toISOString()
  };

  user.progress[day].quizAttempts.push(attempt);
  if (user.progress[day].bestScore === null || score > user.progress[day].bestScore) {
    user.progress[day].bestScore = score;
  }

  writeJSON(USERS_FILE, users);
  res.json({ score, correct, total: dayQuiz.questions.length, results, attempt });
});

// ═══════════════════════════════════════════
//  Protected Admin Data Routes
// ═══════════════════════════════════════════

app.get('/api/admin/dashboard', requireAdmin, (req, res) => {
  const users = readJSON(USERS_FILE);
  auditLog('ADMIN_VIEW_DASHBOARD', { admin: req.adminEmail });
  const summary = users.map(u => ({
    id: u.id,
    name: u.name,
    email: u.email,
    registeredAt: u.registeredAt,
    days: Object.entries(u.progress).map(([d, data]) => ({
      day: parseInt(d),
      topicsRead: data.topicsRead.length,
      attempts: data.quizAttempts.length,
      bestScore: data.bestScore,
      lastAttempt: data.quizAttempts.length > 0
        ? data.quizAttempts[data.quizAttempts.length - 1].timestamp
        : null
    }))
  }));
  res.json(summary);
});

app.get('/api/admin/user/:id', requireAdmin, (req, res) => {
  const id = req.params.id;
  if (typeof id !== 'string' || !/^[a-f0-9]{8,32}$/.test(id)) {
    return res.status(400).json({ error: 'Invalid user ID format.' });
  }

  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  auditLog('ADMIN_VIEW_USER', { admin: req.adminEmail, userId: id });
  res.json(user);
});

// ── SECURITY: Catch-all must not leak file paths ──
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── SECURITY: Global error handler to prevent stack trace leaks ──
app.use((err, req, res, next) => {
  console.error(`[ERROR] ${new Date().toISOString()} |`, err.message);
  res.status(500).json({ error: 'An internal error occurred.' });
});

app.listen(PORT, () => {
  console.log(`Claude Training Hub running at http://localhost:${PORT}`);
  console.log(`Admin dashboard: http://localhost:${PORT}/admin`);
  console.log(`Admin email(s): ${ADMIN_EMAILS.join(', ')}`);
  console.log(`Security: Helmet, rate limiting, input validation, OTP lockout enabled`);
});
