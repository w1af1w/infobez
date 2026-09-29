const {
    validateLogin,
    validatePassword
} = require('../src/server.js');
test('правильный логин проходит проверку', () => {
    expect(validateLogin('user123')).toEqual([]);
});
test('слишком короткий логин не проходит', () => {
    expect(validateLogin('ab')).toContain(
        'Логин должен содержать минимум 3 символа.'
    );
});
test('слишком длинный логин не проходит', () => {
    const login = 'a'.repeat(31);
    expect(validateLogin(login)).toContain(
        'Логин не должен содержать больше 30 символов.'
    );
});
test('логин с недопустимыми символами не проходит', () => {
    expect(validateLogin('user@123')).toContain(
        'Логин содержит недопустимые символы.'
    );
});
test('правильный пароль проходит проверку', () => {
    expect(validatePassword('Xk7!mP92')).toEqual([]);
});
test('слишком короткий пароль не проходит', () => {
    expect(validatePassword('Aa1!')).toContain(
        'Пароль должен содержать минимум 8 символов.'
    );
});
test('слишком длинный пароль не проходит', () => {
    const password = 'Aa1!' + 'x'.repeat(126);
    expect(validatePassword(password)).toContain(
        'Пароль не должен содержать больше 128 символов.'
    );
});
test('пароль без заглавной буквы не проходит', () => {
    expect(validatePassword('password123!')).toContain(
        'Пароль должен содержать заглавную букву.'
    );
});
test('пароль без строчной буквы не проходит', () => {
    expect(validatePassword('PASSWORD123!')).toContain(
        'Пароль должен содержать строчную букву.'
    );
});
test('пароль без цифры не проходит', () => {
    expect(validatePassword('Password!')).toContain(
        'Пароль должен содержать цифру.'
    );
});
test('пароль без специального символа не проходит', () => {
    expect(validatePassword('Password123')).toContain(
        'Пароль должен содержать специальный символ.'
    );
});
test('пароль с клавиатурной последовательностью (латиница) не проходит', () => {
    expect(validatePassword('Qwerty123!')).toContain(
        'Пароль содержит клавиатурную последовательность.'
    );
});
test('пароль с клавиатурной последовательностью (кириллица) не проходит', () => {
    expect(validatePassword('Йцукен123!')).toContain(
        'Пароль содержит клавиатурную последовательность.'
    );
});
test('распространённый пароль не проходит', () => {
    const result = validatePassword('password');
    expect(result).toContain('Пароль слишком распространённый.');
});