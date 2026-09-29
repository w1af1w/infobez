document.getElementById('loginForm').addEventListener('submit', async function(event) {
    event.preventDefault();

    const login = document.getElementById('login').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                login: login,
                password: password
            })
        });

        const result = await response.json();

        alert(result.message);
    } catch (error) {
        alert('Не удалось подключиться к серверу');
        console.error(error);
    }
});