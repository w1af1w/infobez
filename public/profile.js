let refreshPromise = null;
let tokenTimer = null;

async function refreshAccessToken() {
    if (!refreshPromise) {
        refreshPromise = (async () => {
            const response = await fetch('/refresh', {
                method: 'POST',
                credentials: 'include'
            });

            if (!response.ok) {
                return null;
            }

            const data = await response.json();
            setAccessToken(data.accessToken);

            return data.accessToken;
        })().finally(() => {
            refreshPromise = null;
        });
    }

    return refreshPromise;
}

async function fetchWithAuth(url, options = {}) {
    let token = getAccessToken();

    if (!token) {
        token = await refreshAccessToken();

        if (!token) {
            handleSessionExpired();
            return null;
        }
    }

    options.headers = {
        ...options.headers,
        Authorization: `Bearer ${token}`
    };

    let response = await fetch(url, options);

    if (response.status === 401) {
        token = await refreshAccessToken();

        if (!token) {
            handleSessionExpired();
            return null;
        }

        options.headers = {
            ...options.headers,
            Authorization: `Bearer ${token}`
        };

        response = await fetch(url, options);
    }

    if (response.status === 401) {
        handleSessionExpired();
        return null;
    }

    return response;
}

function handleSessionExpired() {
    clearAccessToken();

    if (tokenTimer) {
        clearInterval(tokenTimer);
        tokenTimer = null;
    }

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
                Authorization: `Bearer ${getAccessToken()}`
            }
        });
    } catch (error) {
        console.error('Ошибка при выходе:', error);
    } finally {
        clearAccessToken();

        if (tokenTimer) {
            clearInterval(tokenTimer);
        }

        window.location.href = '/index.html';
    }
});

document.getElementById('activityBtn').addEventListener('click', async () => {
    const response = await fetchWithAuth('/profile');

    if (response && response.ok) {
        console.log('Активность зафиксирована');
    }
});

function startTokenTimer() {
    if (tokenTimer) {
        clearInterval(tokenTimer);
    }

    tokenTimer = setInterval(async () => {
        const token = getAccessToken();

        if (!token) {
            clearInterval(tokenTimer);
            tokenTimer = null;
            return;
        }

        try {
            const payload = JSON.parse(
                atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))
            );

            const remaining = payload.exp - Math.floor(Date.now() / 1000);

            if (remaining <= 0) {
                clearInterval(tokenTimer);
                tokenTimer = null;

                const newToken = await refreshAccessToken();

                if (!newToken) {
                    handleSessionExpired();
                    return;
                }

                startTokenTimer();
            }
        } catch (error) {
            console.error('Ошибка обновления токена:', error);
            handleSessionExpired();
        }
    }, 1000);
}

loadProfile().then(() => {
    if (getAccessToken()) {
        startTokenTimer();
    }
});