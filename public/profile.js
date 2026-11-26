async function fetchWithAuth(url, options = {}) {
    if (!getAccessToken()) {
        return await tryRefreshToken(url, options);
    }
    options.headers = {
        ...options.headers,
        'Authorization': `Bearer ${getAccessToken()}`
    };
    let response = await fetch(url, options);

    if (response.status === 401) {
        return await tryRefreshToken(url, options);
    }
    return response;
}
async function tryRefreshToken(url, options) {
    try {
        const refreshResponse = await fetch('/refresh', {
            method: 'POST',
            credentials: 'include'
        });
        if (!refreshResponse.ok) {
            handleSessionExpired();
            return null;
        }
        const data = await refreshResponse.json();
        setAccessToken(data.accessToken);
        options.headers = {
            ...options.headers,
            'Authorization': `Bearer ${getAccessToken()}`
        };
        const response = await fetch(url, options);
        if (response.status === 401) {
            handleSessionExpired();
            return null;
        }
        return response;
    } catch (error) {
        console.error('Ошибка обновления токена:', error);
        handleSessionExpired();
        return null;
    }
}
function handleSessionExpired() {
    clearAccessToken();
    alert('Сессия истекла. Войдите снова.');
    window.location.href = '/index.html';
}
async function loadProfile() {
    const response = await fetchWithAuth('/profile');
    if (!response) return;
    if (response.ok) {
        const data = await response.json();
        document.getElementById('userLogin').textContent = data.login;
        document.getElementById('loading').style.display = 'none';
        document.getElementById('profileData').style.display = 'block';
    } else {
        handleSessionExpired();
    }
}
document.getElementById('logoutBtn').addEventListener('click', async () => {
    try {
        await fetch('/logout', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Authorization': `Bearer ${getAccessToken()}`
            }
        });
    } catch (error) {
        console.error('Ошибка при выходе:', error);
    } finally {
        clearAccessToken();
        window.location.href = '/index.html';
    }
});
document.getElementById('activityBtn').addEventListener('click', async () => {
    const response = await fetchWithAuth('/profile');
    if (response && response.ok) {
        console.log('Активность продлена на 1 минуту');
    }
});
function startTokenTimer() {
    const timer = setInterval(() => {
        const token = getAccessToken();
        if (!token) {
            clearInterval(timer);
            return;
        }
        const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
        const remaining = payload.exp - Math.floor(Date.now() / 1000);
        if (remaining <= 0) {
            clearInterval(timer);
            handleSessionExpired();
        }
    }, 1000);
}
loadProfile().then(() => startTokenTimer());