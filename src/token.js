const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const JWT_SECRET = process.env.JWT_SECRET;
const ACCESS_TOKEN_LIFETIME = '15m';
const activeAccessTokens = new Map();
function generateRefreshToken() {
    const token = crypto.randomBytes(40).toString('hex');
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    return { token, hash };
}
function createAccessToken(userId) {
    const tokenId = crypto.randomUUID(); 
    const token = jwt.sign(
        { userId, tokenId }, 
        JWT_SECRET, 
        { expiresIn: ACCESS_TOKEN_LIFETIME }
    );
    activeAccessTokens.set(userId, tokenId);
    return token;
}
function removeAccessToken(userId) {
    activeAccessTokens.delete(userId);
}
function getActiveTokenId(userId) {
    return activeAccessTokens.get(userId);
}
function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}
module.exports = {
    generateRefreshToken,
    createAccessToken,
    removeAccessToken,
    getActiveTokenId,
    hashToken,
    JWT_SECRET
};