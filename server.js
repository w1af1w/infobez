const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const app = express();
const PORT = 3000;
const db = new DatabaseSync('./bd_info.db');
const commonPasswords = fs
    .readFileSync('./common-passwords.txt', 'utf8')
    .split('\n')
    .map(password => password.trim().toLowerCase())
    .filter(password => password !== '');
app.use(express.json());
app.use(express.static(__dirname));
const MAX_ATTEMPTS = 3;
const BLOCK_TIME = 60 * 1000;
const loginAttempts = new Map();
function registerFailedAttempt(login) {
    const currentTime = Date.now();
    let attempt = loginAttempts.get(login);
    if (!attempt) {
        attempt = {
            count: 0,
            blocked: false,
            lastAttempt: currentTime
        };
    }
    attempt.count++;
    attempt.lastAttempt = currentTime;
    if (attempt.count >= MAX_ATTEMPTS) {
        attempt.blocked = true;
    }
    loginAttempts.set(login, attempt);
}
app.post('/register', async (req, res) => {
    const { login, password } = req.body;
    if (!login || !password) {
        return res.status(400).json({
            message: 'Заполните все поля'
        });
    }
    const passwordErrors = [];
    if (password.length < 8) {
        passwordErrors.push('• минимум 8 символов');
    }
    if (!/[A-Z]/.test(password)) {
        passwordErrors.push('• хотя бы одна заглавная буква A-Z');
    }
    if (!/[a-z]/.test(password)) {
        passwordErrors.push('• хотя бы одна строчная буква a-z');
    }
    if (!/[0-9]/.test(password)) {
        passwordErrors.push('• хотя бы одна цифра');
    }
    if (!/[@#$%^&*!]/.test(password)) {
        passwordErrors.push('• хотя бы один специальный символ: @ # $ % ^ & * !');
    }
    if (commonPasswords.includes(password.toLowerCase())) {
        passwordErrors.push('• пароль не должен быть распространённым');
    }
    if (passwordErrors.length > 0) {
        return res.status(400).json({
            message:
                'Пароль должен соответствовать требованиям:\n' +
                passwordErrors.join('\n')
        });
    }
    try {
        const checkUser = db.prepare(`
            SELECT id
            FROM users
            WHERE login = ?
        `);
        const user = checkUser.get(login);
        if (user) {
            return res.status(400).json({
                message: 'Такой логин уже существует'
            });
        }
        const passwordHash = await bcrypt.hash(password,10);
        const insertUser = db.prepare(`
            INSERT INTO users (login, password_hash)
            VALUES (?, ?)
        `);
        insertUser.run(
            login,
            passwordHash
        );
        res.json({
            message: 'Регистрация успешна!'
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'Ошибка сервера'
        });
    }
});
app.post('/login', async (req, res) => {
    const { login, password } = req.body;
    if (!login || !password) {
        return res.status(400).json({
            message: 'Введите логин и пароль'
        });
    }
    const attempt = loginAttempts.get(login);
    if (attempt) {
        const currentTime = Date.now();
        const timePassed = currentTime - attempt.lastAttempt;
        if (attempt.blocked && timePassed < BLOCK_TIME) {
            const secondsLeft = Math.ceil(
                (BLOCK_TIME - timePassed) / 1000
            );
            return res.status(429).json({
                message:
                    'Слишком много неправильных попыток.\n' +
                    `Попробуйте снова через ${secondsLeft} секунд.`
            });
        }
        if (timePassed >= BLOCK_TIME) {
            loginAttempts.delete(login);
        }
    }
    try {
        const findUser = db.prepare(`
            SELECT *
            FROM users
            WHERE login = ?
        `);
        const user = findUser.get(login);
        if (!user) {
            registerFailedAttempt(login);
            return res.status(401).json({message: 'Неверный логин или пароль'});
        }
        const passwordCorrect = await bcrypt.compare(password, user.password_hash);
        if (!passwordCorrect) {
            registerFailedAttempt(login);
            return res.status(401).json({
                message: 'Неверный логин или пароль'
            });
        }
        loginAttempts.delete(login);
        res.json({
            message: 'Вход выполнен успешно!'
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({message: 'Ошибка сервера'});
    }
});
app.listen(PORT, () => {
    console.log(`Сервер запущен: http://localhost:${PORT}`);
});