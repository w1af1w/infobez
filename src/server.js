const express = require('express');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const argon2 = require('argon2');
const isCommonPassword = require('common-password');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken'); 
require('dotenv').config();
const { 
    generateRefreshToken, 
    createAccessToken, 
    removeAccessToken, 
    hashToken,
    JWT_SECRET
} = require('./token');
const { createAuthMiddleware } = require('./authMiddleware');
const app = express();
const PORT = 3000;
const db = new DatabaseSync(
    path.join(__dirname, '..', 'database', 'bd_info.db')
);
db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        refresh_token_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_activity INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
`);
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use(cookieParser());
const authenticateToken = createAuthMiddleware(db);
const MAX_ATTEMPTS = 3;
const BLOCK_TIME = 60 * 1000;
const SESSION_LIFETIME = 8 * 60 * 60 * 1000; // 8 часов
const INACTIVITY_LIFETIME = 1 * 60 * 1000; // 15 минут
const ARGON2_OPTIONS = {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1
};
const loginAttempts = new Map();
function validatePassword(password) {
    const errors = [];
    if (password.length < 8) errors.push('Пароль должен содержать минимум 8 символов.');
    if (password.length > 128) errors.push('Пароль не должен содержать больше 128 символов.');
    if (!/[A-ZА-Я]/.test(password)) errors.push('Пароль должен содержать заглавную букву.');
    if (!/[a-zа-я]/.test(password)) errors.push('Пароль должен содержать строчную букву.');
    if (!/[0-9]/.test(password)) errors.push('Пароль должен содержать цифру.');
    if (!/[@#$%^&*!]/.test(password)) errors.push('Пароль должен содержать специальный символ.');
    try {
        if (isCommonPassword(password)) errors.push('Пароль слишком распространённый.');
    } catch (error) {
        console.warn('common-password недоступен:', error.message);
    }
    const keyboardPatterns = ['qwerty', 'asdfgh', 'zxcvbn', 'йцукен', 'фывапр', 'ячсмить'];
    for (let i = 0; i < keyboardPatterns.length; i++) {
        if (password.toLowerCase().includes(keyboardPatterns[i])) {
            errors.push('Пароль содержит клавиатурную последовательность.');
            break;
        }
    }
    return errors;
}
function validateLogin(login) {
    const errors = [];
    if (login.length < 3) errors.push('Логин должен содержать минимум 3 символа.');
    if (login.length > 30) errors.push('Логин не должен содержать больше 30 символов.');
    if (!/^[a-zA-Zа-яА-Я0-9_-]+$/.test(login)) errors.push('Логин содержит недопустимые символы.');
    return errors;
}
app.post('/register', async (req, res) => {
    try {
        const login = req.body.login;
        const password = req.body.password;
        if (!login || !password) return res.status(400).json({ message: 'Заполните все поля.' });
        const loginErrors = validateLogin(login);
        if (loginErrors.length > 0) return res.status(400).json({ message: loginErrors.join('\n') });
        const passwordErrors = validatePassword(password);
        if (passwordErrors.length > 0) return res.status(400).json({ message: passwordErrors.join('\n') });
        const existingUser = db.prepare('SELECT id FROM users WHERE login = ?').get(login);
        if (existingUser) return res.status(400).json({ message: 'Пользователь с таким логином уже существует.' });
        const passwordHash = await argon2.hash(password, ARGON2_OPTIONS);
        db.prepare(`INSERT INTO users (login, password_hash) VALUES (?, ?)`).run(login, passwordHash);
        res.json({ message: 'Регистрация прошла успешно!' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});
app.post('/login', async (req, res) => {
    try {
        const login = req.body.login;
        const password = req.body.password;
        if (!login || !password) return res.status(400).json({ message: 'Введите логин и пароль.' });
        const attempt = loginAttempts.get(login);
        if (attempt) {
            const currentTime = Date.now();
            const timePassed = currentTime - attempt.time;
            if (attempt.count >= MAX_ATTEMPTS) {
                if (timePassed < BLOCK_TIME) {
                    const secondsLeft = Math.ceil((BLOCK_TIME - timePassed) / 1000);
                    return res.status(429).json({ message: `Слишком много попыток. Повторите через ${secondsLeft} сек.` });
                }
                loginAttempts.delete(login);
            }
        }
        const user = db.prepare(`SELECT id, login, password_hash FROM users WHERE login = ?`).get(login);
        if (!user) {
            let currentAttempt = loginAttempts.get(login) || { count: 0, time: Date.now() };
            currentAttempt.count++;
            currentAttempt.time = Date.now();
            loginAttempts.set(login, currentAttempt);
            return res.status(401).json({ message: 'Неверный логин или пароль.' });
        }
        const passwordCorrect = await argon2.verify(user.password_hash, password);
        if (!passwordCorrect) {
            let currentAttempt = loginAttempts.get(login) || { count: 0, time: Date.now() };
            currentAttempt.count++;
            currentAttempt.time = Date.now();
            loginAttempts.set(login, currentAttempt);
            if (currentAttempt.count >= MAX_ATTEMPTS) {
                return res.status(429).json({ message: 'Слишком много неправильных попыток. Вход заблокирован на 60 секунд.' });
            }
            return res.status(401).json({ message: 'Неверный логин или пароль.' });
        }
        loginAttempts.delete(login);
        const now = Date.now();
        const expiresAt = now + SESSION_LIFETIME;
        const { token: refreshToken, hash: refreshHash } = generateRefreshToken();
        db.prepare(`
            INSERT INTO sessions (user_id, refresh_token_hash, created_at, last_activity, expires_at)
            VALUES (?, ?, ?, ?, ?)
        `).run(user.id, refreshHash, now, now, expiresAt);
        const accessToken = createAccessToken(user.id);
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', 
            sameSite: 'strict',
            maxAge: SESSION_LIFETIME
        });
        return res.json({ message: 'Вход выполнен успешно!', accessToken: accessToken });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});
app.get('/profile', authenticateToken, (req, res) => {
    const user = db.prepare('SELECT login FROM users WHERE id = ?').get(req.user.userId);
    if (!user) return res.status(404).json({ message: 'Пользователь не найден' });
    res.json({ login: user.login });
});
app.post('/refresh', (req, res) => {
    const oldRefreshToken = req.cookies.refreshToken;
    if (!oldRefreshToken) return res.status(401).json({ message: 'Нет Refresh-токена' });
    const oldHash = hashToken(oldRefreshToken);
    const session = db.prepare(`SELECT * FROM sessions WHERE refresh_token_hash = ?`).get(oldHash);
    if (!session) return res.status(403).json({ message: 'Недействительный Refresh-токен' });
    const now = Date.now();
    if (now > session.expires_at || (now - session.last_activity) > INACTIVITY_LIFETIME) {
        db.prepare('DELETE FROM sessions WHERE id = ?').run(session.id);
        return res.status(401).json({ message: 'Сессия истекла. Войдите снова' });
    }
    const { token: newRefreshToken, hash: newHash } = generateRefreshToken();
    const newAccessToken = createAccessToken(session.user_id);
    db.prepare(`UPDATE sessions SET refresh_token_hash = ? WHERE id = ?`).run(newHash, session.id);
    res.cookie('refreshToken', newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: SESSION_LIFETIME
    });
    res.json({ accessToken: newAccessToken });
});
app.post('/logout', (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
        const hash = hashToken(refreshToken);
        db.prepare('DELETE FROM sessions WHERE refresh_token_hash = ?').run(hash);
    }
    const authHeader = req.headers['authorization'];
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            removeAccessToken(decoded.userId);
        } catch (e) {} 
    }
    res.clearCookie('refreshToken');
    res.json({ message: 'Выход выполнен успешно' });
});
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Сервер запущен: http://localhost:${PORT}`);
    });
}
module.exports = { app, validateLogin, validatePassword };