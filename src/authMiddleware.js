const jwt = require('jsonwebtoken');
const { getActiveTokenId, JWT_SECRET } = require('./token');

function createAuthMiddleware(db) {
    return function authenticateToken(req, res, next) {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: 'Требуется авторизация' });
        }

        try {
            const decoded = jwt.verify(token, JWT_SECRET);

            const currentTokenId = getActiveTokenId(decoded.userId);

            if (currentTokenId !== decoded.tokenId) {
                return res.status(401).json({ message: 'Токен недействителен (устарел)' });
            }

            const now = Date.now();

            const session = db.prepare(`
                SELECT * FROM sessions
                WHERE user_id = ? AND expires_at > ?
                ORDER BY id DESC LIMIT 1
            `).get(decoded.userId, now);

            if (!session) {
                return res.status(401).json({ message: 'Сессия истекла' });
            }

            db.prepare(`
                UPDATE sessions
                SET last_activity = ?
                WHERE id = ?
            `).run(now, session.id);

            req.user = decoded;
            next();

        } catch (err) {
            return res.status(401).json({ message: 'Недействительный токен' });
        }
    };
}

module.exports = { createAuthMiddleware };