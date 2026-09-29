const argon2 = require('argon2');

const PASSWORD = 'Xk7!mP92';

const OPTIONS = {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1
};

async function measureHash() {
    const start = process.hrtime.bigint();

    const hash = await argon2.hash(PASSWORD, OPTIONS);

    const end = process.hrtime.bigint();

    return {
        hash: hash,
        time: Number(end - start) / 1000000
    };
}

async function measureVerify(hash) {
    const start = process.hrtime.bigint();

    await argon2.verify(hash, PASSWORD);

    const end = process.hrtime.bigint();

    return Number(end - start) / 1000000;
}

async function measureUsers(count, hash) {
    const tasks = [];

    const start = process.hrtime.bigint();

    for (let i = 0; i < count; i++) {
        tasks.push(argon2.verify(hash, PASSWORD));
    }

    await Promise.all(tasks);

    const end = process.hrtime.bigint();

    return Number(end - start) / 1000000;
}

async function runBenchmark() {
    console.log('БЕНЧМАРК ARGON2');
    console.log('================');

    const hashResult = await measureHash();

    console.log(
        `Hash одного пароля: ${hashResult.time.toFixed(2)} мс`
    );

    const verifyTime = await measureVerify(hashResult.hash);

    console.log(
        `Verify одного пароля: ${verifyTime.toFixed(2)} мс`
    );

    console.log('');
    console.log('БЕНЧМАРК НЕСКОЛЬКИХ ПОЛЬЗОВАТЕЛЕЙ');
    console.log('=================================');

    const userCounts = [1, 5, 10, 20];

    for (let i = 0; i < userCounts.length; i++) {
        const count = userCounts[i];

        const time = await measureUsers(
            count,
            hashResult.hash
        );

        console.log(
            `${count} пользователей: ${time.toFixed(2)} мс`
        );
    }
}

runBenchmark();