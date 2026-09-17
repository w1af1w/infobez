const express = require('express');
const { DatabaseSync } = require('node:sqlite');
//раньше использовался bcryptjs
const argon2 = require('argon2');
const fs = require('fs');
//добавлен crypto для создания случайного ключа сессии.
const crypto = require('crypto');
const app = express();
const PORT = 3000;
const db = new DatabaseSync('./bd_info.db');
const commonPasswords = fs //отдельную таблицу в бд сделать для слов!
    .readFileSync('./common-passwords.txt', 'utf8')
    .split('\n')
    .map(password => password.trim().toLowerCase())
    .filter(password => password !== '');
app.use(express.json());
app.use(express.static(__dirname));
const MAX_ATTEMPTS = 3;
const BLOCK_TIME = 60 * 1000;
//добавлено время жизни одной сессии — 3 сек
const SESSION_TIME = 3 * 1000;
const loginAttempts = new Map();
//добавлено временное хранение активных сессий
const sessions = new Map();
const ARGON2_OPTIONS = {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1
};
function validatePassword(password) {
    const errors = [];
    if (password.length < 8) {
        errors.push('Пароль должен содержать минимум 8 символов.');
    }
    if (password.length > 128) {
        errors.push('Пароль не должен содержать больше 128 символов.');
    }
    if (!/[A-ZА-Я]/.test(password)) {
        errors.push('Пароль должен содержать заглавную букву.');
    }
    if (!/[a-zа-я]/.test(password)) {
        errors.push('Пароль должен содержать строчную букву.');
    }
    if (!/[0-9]/.test(password)) {
        errors.push('Пароль должен содержать цифру.');
    }
    if (!/[@#$%^&*!]/.test(password)) {
        errors.push('Пароль должен содержать специальный символ.');
    }
    if (commonPasswords.includes(password.toLowerCase())) {
        errors.push('Пароль слишком распространённый.');
    }
    const keyboardPatterns = [
        'qwerty',
        'asdfgh',
        'zxcvbn',
        'йцукен',
        'фывапр',
        'ячсмить'
    ];
    for (let i = 0; i < keyboardPatterns.length; i++) {
        if (password.toLowerCase().includes(keyboardPatterns[i])) {
            errors.push('Пароль содержит клавиатурную последовательность.');
            break;
        }
    }
    return errors;
}
//добавлена проверка логина
function validateLogin(login) {
    const errors = [];
    if (login.length < 3) {
        errors.push('Логин должен содержать минимум 3 символа.');
    }
    if (login.length > 30) {
        errors.push('Логин не должен содержать больше 30 символов.');
    }
    if (!/^[a-zA-Zа-яА-Я0-9_-]+$/.test(login)) {
        errors.push('Логин содержит недопустимые символы.');
    }
    return errors;
}
app.post('/register', async (req, res) => {
    try {
        const login = req.body.login;
        const password = req.body.password;
        if (!login || !password) {
            return res.status(400).json({
                message: 'Заполните все поля.'
            });
        }
        const loginErrors = validateLogin(login);
        if (loginErrors.length > 0) {
            return res.status(400).json({
                message: loginErrors.join('\n')
            });
        }
        const passwordErrors = validatePassword(password);
        if (passwordErrors.length > 0) {
            return res.status(400).json({
                message: passwordErrors.join('\n')
            });
        }
        const existingUser = db
            .prepare('SELECT id FROM users WHERE login = ?')
            .get(login);
        if (existingUser) {
            return res.status(400).json({
                message: 'Пользователь с таким логином уже существует.'
            });
        }
        //раньше использовался bcrypt.hash()
        //теперь пароль хешируется с помощью argon2
        //argon2 автоматически создаёт соль
        //cоль хранится внутри строки хеша
        const passwordHash = await argon2.hash(
            password,
            ARGON2_OPTIONS
        );
        db.prepare(`
            INSERT INTO users (login, password_hash)
            VALUES (?, ?)
        `).run(login, passwordHash);
        res.json({
            message: 'Регистрация прошла успешно!'
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'Ошибка сервера.'
        });
    }
});
app.post('/login', async (req, res) => {
    try {
        const login = req.body.login;
        const password = req.body.password;
        if (!login ||!password) {
            return res.status(400).json({
                message: 'Введите логин и пароль.'
            });
        }
        const attempt = loginAttempts.get(login);
        if (attempt) {
            const currentTime = Date.now();
            const timePassed = currentTime - attempt.time;
            if (attempt.count >= MAX_ATTEMPTS) {
                if (timePassed < BLOCK_TIME) {
                    const secondsLeft = Math.ceil(
                        (BLOCK_TIME - timePassed) / 1000
                    );
                    return res.status(429).json({
                        message:
                            `Слишком много попыток. Повторите через ${secondsLeft} сек.`
                    });
                } else {
                    loginAttempts.delete(login);
                }
            }
        }
        const user = db
            .prepare(`
                SELECT id, login, password_hash
                FROM users
                WHERE login = ?
            `)
            .get(login);
        if (!user) {
            let currentAttempt = loginAttempts.get(login);
            if (!currentAttempt) {
                currentAttempt = {
                    count: 0,
                    time: Date.now()
                };
            }
            currentAttempt.count++;
            currentAttempt.time = Date.now();
            loginAttempts.set(login, currentAttempt);
            return res.status(401).json({
                message: 'Неверный логин или пароль.'
            });
        }
        const passwordCorrect = await argon2.verify(
            user.password_hash,
            password
        );
        if (!passwordCorrect) {
            let currentAttempt = loginAttempts.get(login);
            if (!currentAttempt) {
                currentAttempt = {
                    count: 0,
                    time: Date.now()
                };
            }
            currentAttempt.count++;
            currentAttempt.time = Date.now();
            loginAttempts.set(login, currentAttempt);
            if (currentAttempt.count >= MAX_ATTEMPTS) {
                return res.status(429).json({
                    message: 'Слишком много неправильных попыток. Вход заблокирован на 60 секунд.'
                });
            }
            return res.status(401).json({
                message: 'Неверный логин или пароль.'
            });
        }
        //добавлено удаление старых неудачных попыток после успешного входа
        loginAttempts.delete(login);
        //добавлено создание случайного ключа сессии
        const sessionKey = crypto.randomBytes(32).toString('hex');
        const currentTime = Date.now();
        sessions.set(sessionKey, {
            login: user.login,
            createdAt: currentTime,
            lastActivity: currentTime
        });
        res.json({
            message: 'Вход выполнен успешно!',
            sessionKey: sessionKey,
            expiresIn: SESSION_TIME
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            message: 'Ошибка сервера.'
        });
    }
});
//добавлена проверка существования sessionKey и его срока действия
function checkSession(req, res, next) {
    const sessionKey = req.headers['x-session-key'];
    if (!sessionKey) {
        return res.status(401).json({
            message: 'Необходимо выполнить вход.'
        });
    }
    const session = sessions.get(sessionKey);
    if (!session) {
        return res.status(401).json({
            message: 'Сессия недействительна.'
        });
    }
    const currentTime = Date.now();
    const timePassed = currentTime - session.createdAt;
    if (timePassed > SESSION_TIME) {
        sessions.delete(sessionKey);
        return res.status(401).json({
            message: 'Сессия истекла. Выполните вход снова.'
        });
    }
    session.lastActivity = currentTime;
    req.user = session.login;
    next();
}
//добавлено: доступ к профилю возможен только при наличии действительной сессии
app.get('/profile', checkSession, (req, res) => {
    res.json({
        message: 'Доступ разрешён',
        login: req.user
    });
});
//добавлено: при выходе удаляем sessionKey. после этого старый ключ больше не работает.
app.post('/logout', (req, res) => {
    const sessionKey = req.headers['x-session-key'];
    if (sessionKey) {
        sessions.delete(sessionKey);
    }
res.json({message: 'Выход выполнен'});
});
app.listen(PORT, () => {
    console.log(
        `Сервер запущен: http://localhost:${PORT}`
    );
})