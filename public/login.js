async function restoreSession() {
    try {
        const response = await fetch('/refresh', {
            method: 'POST',
            credentials: 'include'
        });
        if (response.ok) {
            const data = await response.json();
            setAccessToken(data.accessToken);
            window.location.replace('/profile.html');
        }
    } catch (error) {
        console.error('Ошибка восстановления сессии:', error);
    }
}
document.addEventListener('DOMContentLoaded', () => {
    restoreSession();
    document.getElementById('loginForm').addEventListener('submit', async function(event) {
        event.preventDefault();
        const login = document.getElementById('login').value;
        const password = document.getElementById('password').value;
        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ login, password })
            });
            const result = await response.json();
            if (response.ok) {
                setAccessToken(result.accessToken);
                window.location.href = '/profile.html';
            } else {
                alert(result.message);
            }
        } catch (error) {
            alert('Не удалось подключиться к серверу');
            console.error(error);
        }
    });
});