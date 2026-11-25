let accessToken = null;
function setAccessToken(token) {
    accessToken = token;
}

function getAccessToken() {
    return accessToken;
}

function clearAccessToken() {
    accessToken = null;
}