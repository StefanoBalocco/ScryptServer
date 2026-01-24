import test from 'ava';
import path from 'path';
import workerpool from 'workerpool';
const defaultParams = {
    cost: 4096,
    blockSize: 8,
    parallelization: 1,
    saltlen: 16,
    keylen: 32
};
let pool;
test.before(() => {
    pool = workerpool.pool(path.join(import.meta.dirname, '..', '..', 'dist', 'Worker.js'), { minWorkers: 1, maxWorkers: 2 });
});
test.after.always(async () => {
    await pool.terminate();
});
test.serial('hash: generates valid hash with default parameters', async (t) => {
    const result = await pool.exec('hash', ['password123', defaultParams]);
    t.truthy(result);
    t.is(typeof result, 'string');
    const buffer = Buffer.from(result, 'base64');
    t.truthy(buffer.length > 0);
    t.is(buffer[0], 0x02);
});
test.serial('hash: generates different hashes for same password (random salt)', async (t) => {
    const hash1 = await pool.exec('hash', ['password123', defaultParams]);
    const hash2 = await pool.exec('hash', ['password123', defaultParams]);
    t.not(hash1, hash2);
});
test.serial('hash: correct output length', async (t) => {
    const params = { cost: 4096, blockSize: 1, parallelization: 1, saltlen: 20, keylen: 64 };
    const result = await pool.exec('hash', ['test', params]);
    const buffer = Buffer.from(result, 'base64');
    t.is(buffer.length, 4 + params.saltlen + params.keylen);
});
test.serial('hash: error with empty data', async (t) => {
    await t.throwsAsync(() => pool.exec('hash', ['', defaultParams]), { message: /Missing, invalid or too much data/ });
});
test.serial('hash: error with data too long (>2048 characters)', async (t) => {
    const longData = 'a'.repeat(2049);
    await t.throwsAsync(() => pool.exec('hash', [longData, defaultParams]), { message: /Missing, invalid or too much data/ });
});
test.serial('hash: accepts data of 2048 characters', async (t) => {
    const maxData = 'a'.repeat(2048);
    const result = await pool.exec('hash', [maxData, defaultParams]);
    t.truthy(result);
});
test.serial('hash: error with cost too low', async (t) => {
    const params = { ...defaultParams, cost: 2048 };
    await t.throwsAsync(() => pool.exec('hash', ['test', params]), { message: /Invalid cost parameter/ });
});
test.serial('hash: error with cost too high', async (t) => {
    const params = { ...defaultParams, cost: 1048576 };
    await t.throwsAsync(() => pool.exec('hash', ['test', params]), { message: /Invalid cost parameter/ });
});
test.serial('hash: error with cost not power of 2', async (t) => {
    const params = { ...defaultParams, cost: 5000 };
    await t.throwsAsync(() => pool.exec('hash', ['test', params]), { message: /Invalid cost.*power of 2/ });
});
test.serial('hash: accepts minimum cost (4096)', async (t) => {
    const params = { ...defaultParams, cost: 4096 };
    const result = await pool.exec('hash', ['test', params]);
    t.truthy(result);
});
test.serial('hash: accepts maximum cost (524288)', async (t) => {
    const params = { ...defaultParams, cost: 524288 };
    const result = await pool.exec('hash', ['test', params]);
    t.truthy(result);
});
test.serial('hash: error with invalid blockSize (0)', async (t) => {
    const params = { ...defaultParams, blockSize: 0 };
    await t.throwsAsync(() => pool.exec('hash', ['test', params]), { message: /Invalid blockSize/ });
});
test.serial('hash: error with invalid blockSize (17)', async (t) => {
    const params = { ...defaultParams, blockSize: 17 };
    await t.throwsAsync(() => pool.exec('hash', ['test', params]), { message: /Invalid blockSize/ });
});
test.serial('hash: accepts valid blockSize range (1-16)', async (t) => {
    for (const blockSize of [1, 8, 16]) {
        const params = { ...defaultParams, blockSize };
        const result = await pool.exec('hash', ['test', params]);
        t.truthy(result, `blockSize ${blockSize} should be valid`);
    }
});
test.serial('hash: error with invalid parallelization (0)', async (t) => {
    const params = { ...defaultParams, parallelization: 0 };
    await t.throwsAsync(() => pool.exec('hash', ['test', params]), { message: /Invalid parallelization/ });
});
test.serial('hash: error with invalid parallelization (17)', async (t) => {
    const params = { ...defaultParams, parallelization: 17 };
    await t.throwsAsync(() => pool.exec('hash', ['test', params]), { message: /Invalid parallelization/ });
});
test.serial('hash: accepts valid parallelization range (1-16)', async (t) => {
    for (const parallelization of [1, 8, 16]) {
        const params = { ...defaultParams, parallelization };
        const result = await pool.exec('hash', ['test', params]);
        t.truthy(result, `parallelization ${parallelization} should be valid`);
    }
});
test.serial('hash: error with saltlen too short (15)', async (t) => {
    const params = { ...defaultParams, saltlen: 15 };
    await t.throwsAsync(() => pool.exec('hash', ['test', params]), { message: /Invalid saltlen/ });
});
test.serial('hash: error with saltlen too long (48)', async (t) => {
    const params = { ...defaultParams, saltlen: 48 };
    await t.throwsAsync(() => pool.exec('hash', ['test', params]), { message: /Invalid saltlen/ });
});
test.serial('hash: accepts valid saltlen range (16-47)', async (t) => {
    for (const saltlen of [16, 32, 47]) {
        const params = { ...defaultParams, saltlen };
        const result = await pool.exec('hash', ['test', params]);
        t.truthy(result, `saltlen ${saltlen} should be valid`);
    }
});
test.serial('hash: error with keylen too short (15)', async (t) => {
    const params = { ...defaultParams, keylen: 15 };
    await t.throwsAsync(() => pool.exec('hash', ['test', params]), { message: /Invalid keylen/ });
});
test.serial('hash: error with keylen too long (272)', async (t) => {
    const params = { ...defaultParams, keylen: 272 };
    await t.throwsAsync(() => pool.exec('hash', ['test', params]), { message: /Invalid keylen/ });
});
test.serial('hash: accepts valid keylen range (16-271)', async (t) => {
    for (const keylen of [16, 64, 271]) {
        const params = { ...defaultParams, keylen };
        const result = await pool.exec('hash', ['test', params]);
        t.truthy(result, `keylen ${keylen} should be valid`);
    }
});
test.serial('compare: verifies correct password', async (t) => {
    const password = 'mySecretPassword';
    const hash = await pool.exec('hash', [password, defaultParams]);
    const result = await pool.exec('compare', [password, hash]);
    t.true(result);
});
test.serial('compare: rejects wrong password', async (t) => {
    const hash = await pool.exec('hash', ['correctPassword', defaultParams]);
    const result = await pool.exec('compare', ['wrongPassword', hash]);
    t.false(result);
});
test.serial('compare: works with various parameters', async (t) => {
    const params = {
        cost: 8192,
        blockSize: 4,
        parallelization: 2,
        saltlen: 24,
        keylen: 48
    };
    const password = 'testPassword';
    const hash = await pool.exec('hash', [password, params]);
    const result = await pool.exec('compare', [password, hash]);
    t.true(result);
});
test.serial('compare: error with empty hash', async (t) => {
    await t.throwsAsync(() => pool.exec('compare', ['password', '']), { message: /Missing or invalid hash/ });
});
test.serial('compare: error with corrupted hash', async (t) => {
    await t.throwsAsync(() => pool.exec('compare', ['password', 'invalidbase64!!!']), { message: /Missing or invalid hash|Invalid hash buffer/ });
});
test.serial('compare: error with hash too short', async (t) => {
    const shortHash = Buffer.from([0x02, 0x00, 0x00]).toString('base64');
    await t.throwsAsync(() => pool.exec('compare', ['password', shortHash]), { message: /Missing or invalid hash buffer/ });
});
test.serial('compare: error with unsupported binary version', async (t) => {
    const fakeHash = Buffer.alloc(52);
    fakeHash[0] = 0x03;
    await t.throwsAsync(() => pool.exec('compare', ['password', fakeHash.toString('base64')]), { message: /Unsupported binary version/ });
});
test.serial('compare: error with empty data', async (t) => {
    const hash = await pool.exec('hash', ['password', defaultParams]);
    await t.throwsAsync(() => pool.exec('compare', ['', hash]), { message: /Missing, invalid or too much data/ });
});
test.serial('compare: error with data too long', async (t) => {
    const hash = await pool.exec('hash', ['password', defaultParams]);
    const longData = 'a'.repeat(2049);
    await t.throwsAsync(() => pool.exec('compare', [longData, hash]), { message: /Missing, invalid or too much data/ });
});
test.serial('binary format: encodes parameters correctly', async (t) => {
    const params = {
        cost: 16384,
        blockSize: 8,
        parallelization: 4,
        saltlen: 20,
        keylen: 32
    };
    const hash = await pool.exec('hash', ['test', params]);
    const buffer = Buffer.from(hash, 'base64');
    t.is(buffer[0], 0x02);
    t.is(buffer[1], (7 << 4) | 3);
    t.is(buffer[2], (2 << 5) | 4);
    t.is(buffer[3], 16);
});
test.serial('binary format: decodes parameters in compare', async (t) => {
    const params = {
        cost: 8192,
        blockSize: 1,
        parallelization: 2,
        saltlen: 16,
        keylen: 16
    };
    const password = 'extremeParams';
    const hash = await pool.exec('hash', [password, params]);
    const result = await pool.exec('compare', [password, hash]);
    t.true(result);
});
test.serial('binary format: minimum values encoded correctly', async (t) => {
    const params = {
        cost: 4096,
        blockSize: 1,
        parallelization: 1,
        saltlen: 16,
        keylen: 16
    };
    const password = 'minParams';
    const hash = await pool.exec('hash', [password, params]);
    const buffer = Buffer.from(hash, 'base64');
    t.is(buffer[0], 0x02);
    t.is(buffer[1], 0x00);
    t.is(buffer[2], 0x00);
    t.is(buffer[3], 0x00);
    const result = await pool.exec('compare', [password, hash]);
    t.true(result);
});
