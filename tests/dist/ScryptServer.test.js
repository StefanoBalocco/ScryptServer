import test from 'ava';
import path from 'path';
import { createTestConfig } from './TestConfig.js';
const serverModule = await import(path.join(import.meta.dirname, '..', '..', 'dist', 'ScryptServer.js'));
const ScryptServer = serverModule.ScryptServer;
const defaultParams = {
    cost: 4096,
    blockSize: 8,
    parallelization: 1,
    saltlen: 16,
    keylen: 32
};
const config = createTestConfig();
const server = new ScryptServer(config);
test.serial('Start: server starts successfully', async (t) => {
    await t.notThrowsAsync(server.Start());
});
test.serial('hash: returns valid hash', async (t) => {
    const result = await server.hash('password123', defaultParams);
    t.falsy(result.error);
    t.truthy(result.result);
    t.is(typeof result.result, 'string');
});
test.serial('hash: generates different hashes for same password (random salt)', async (t) => {
    const result1 = await server.hash('samePassword', defaultParams);
    const result2 = await server.hash('samePassword', defaultParams);
    t.truthy(result1.result);
    t.truthy(result2.result);
    t.not(result1.result, result2.result);
});
test.serial('hash: error with empty data', async (t) => {
    const result = await server.hash('', defaultParams);
    t.truthy(result.error);
    t.falsy(result.result);
});
test.serial('hash: error with data too long (>2048 characters)', async (t) => {
    const longData = 'a'.repeat(2049);
    const result = await server.hash(longData, defaultParams);
    t.truthy(result.error);
    t.falsy(result.result);
});
test.serial('hash: accepts data of 2048 characters', async (t) => {
    const maxData = 'a'.repeat(2048);
    const result = await server.hash(maxData, defaultParams);
    t.falsy(result.error);
    t.truthy(result.result);
});
test.serial('hash: error with cost too low', async (t) => {
    const params = { ...defaultParams, cost: 2048 };
    const result = await server.hash('test', params);
    t.truthy(result.error);
    t.falsy(result.result);
});
test.serial('hash: error with cost too high', async (t) => {
    const params = { ...defaultParams, cost: 1048576 };
    const result = await server.hash('test', params);
    t.truthy(result.error);
    t.falsy(result.result);
});
test.serial('hash: error with cost not power of 2', async (t) => {
    const params = { ...defaultParams, cost: 5000 };
    const result = await server.hash('test', params);
    t.truthy(result.error);
    t.falsy(result.result);
});
test.serial('hash: accepts minimum cost (4096)', async (t) => {
    const params = { ...defaultParams, cost: 4096 };
    const result = await server.hash('test', params);
    t.falsy(result.error);
    t.truthy(result.result);
});
test.serial('hash: error with invalid blockSize (0)', async (t) => {
    const params = { ...defaultParams, blockSize: 0 };
    const result = await server.hash('test', params);
    t.truthy(result.error);
    t.falsy(result.result);
});
test.serial('hash: error with invalid blockSize (17)', async (t) => {
    const params = { ...defaultParams, blockSize: 17 };
    const result = await server.hash('test', params);
    t.truthy(result.error);
    t.falsy(result.result);
});
test.serial('hash: error with invalid parallelization (0)', async (t) => {
    const params = { ...defaultParams, parallelization: 0 };
    const result = await server.hash('test', params);
    t.truthy(result.error);
    t.falsy(result.result);
});
test.serial('hash: error with invalid parallelization (17)', async (t) => {
    const params = { ...defaultParams, parallelization: 17 };
    const result = await server.hash('test', params);
    t.truthy(result.error);
    t.falsy(result.result);
});
test.serial('hash: error with saltlen too short (15)', async (t) => {
    const params = { ...defaultParams, saltlen: 15 };
    const result = await server.hash('test', params);
    t.truthy(result.error);
    t.falsy(result.result);
});
test.serial('hash: error with saltlen too long (48)', async (t) => {
    const params = { ...defaultParams, saltlen: 48 };
    const result = await server.hash('test', params);
    t.truthy(result.error);
    t.falsy(result.result);
});
test.serial('hash: error with keylen too short (15)', async (t) => {
    const params = { ...defaultParams, keylen: 15 };
    const result = await server.hash('test', params);
    t.truthy(result.error);
    t.falsy(result.result);
});
test.serial('hash: error with keylen too long (272)', async (t) => {
    const params = { ...defaultParams, keylen: 272 };
    const result = await server.hash('test', params);
    t.truthy(result.error);
    t.falsy(result.result);
});
test.serial('compare: verifies correct password', async (t) => {
    const hashResult = await server.hash('testPassword', defaultParams);
    t.truthy(hashResult.result);
    const compareResult = await server.compare('testPassword', hashResult.result);
    t.falsy(compareResult.error);
    t.true(compareResult.result);
});
test.serial('compare: rejects wrong password', async (t) => {
    const hashResult = await server.hash('correctPassword', defaultParams);
    t.truthy(hashResult.result);
    const compareResult = await server.compare('wrongPassword', hashResult.result);
    t.falsy(compareResult.error);
    t.false(compareResult.result);
});
test.serial('compare: error with empty data', async (t) => {
    const hashResult = await server.hash('password', defaultParams);
    t.truthy(hashResult.result);
    const compareResult = await server.compare('', hashResult.result);
    t.truthy(compareResult.error);
});
test.serial('compare: error with empty hash', async (t) => {
    const result = await server.compare('password', '');
    t.truthy(result.error);
});
test.serial('compare: error with corrupted hash', async (t) => {
    const result = await server.compare('password', 'notvalidbase64!!!');
    t.truthy(result.error);
});
test.serial('compare: error with hash too short', async (t) => {
    const shortHash = Buffer.from([0x02, 0x00, 0x00]).toString('base64');
    const result = await server.compare('password', shortHash);
    t.truthy(result.error);
});
test.serial('compare: error with unsupported binary version', async (t) => {
    const hashResult = await server.hash('password', defaultParams);
    t.truthy(hashResult.result);
    const fakeHash = Buffer.from(hashResult.result, 'base64');
    fakeHash[0] = 0x03;
    const result = await server.compare('password', fakeHash.toString('base64'));
    t.truthy(result.error);
});
test.serial('compare: error with data too long', async (t) => {
    const hashResult = await server.hash('password', defaultParams);
    t.truthy(hashResult.result);
    const longData = 'a'.repeat(2049);
    const compareResult = await server.compare(longData, hashResult.result);
    t.truthy(compareResult.error);
});
test.serial('compare: works with various parameters', async (t) => {
    const params = {
        cost: 8192,
        blockSize: 4,
        parallelization: 2,
        saltlen: 32,
        keylen: 64
    };
    const hashResult = await server.hash('testPassword', params);
    t.truthy(hashResult.result);
    const compareResult = await server.compare('testPassword', hashResult.result);
    t.falsy(compareResult.error);
    t.true(compareResult.result);
});
test.serial('HTTP /hash: returns valid hash', async (t) => {
    const response = await server.request('/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: 'password123', ...defaultParams })
    });
    t.is(response.status, 200);
    const body = await response.json();
    t.truthy(body.result);
    t.is(typeof body.result, 'string');
});
test.serial('HTTP /hash: error 400 without data', async (t) => {
    const response = await server.request('/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...defaultParams })
    });
    t.is(response.status, 400);
    const body = await response.json();
    t.truthy(body.error);
});
test.serial('HTTP /hash: error 400 with non-string data', async (t) => {
    const response = await server.request('/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: 12345, ...defaultParams })
    });
    t.is(response.status, 400);
    const body = await response.json();
    t.truthy(body.error);
});
test.serial('HTTP /hash: error 400 without parameters', async (t) => {
    const response = await server.request('/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: 'password' })
    });
    t.is(response.status, 400);
    const body = await response.json();
    t.truthy(body.error);
});
test.serial('HTTP /hash: error 400 with non-integer parameters', async (t) => {
    const response = await server.request('/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            data: 'password',
            cost: 'not a number',
            blockSize: 8,
            parallelization: 1,
            saltlen: 16,
            keylen: 32
        })
    });
    t.is(response.status, 400);
    const body = await response.json();
    t.truthy(body.error);
});
test.serial('HTTP /hash: error with malformed JSON', async (t) => {
    const response = await server.request('/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: 'invalid json {'
    });
    t.is(response.status, 400);
    const body = await response.json();
    t.truthy(body.error);
});
test.serial('HTTP /hash: handles invalid parameters (cost too low)', async (t) => {
    const response = await server.request('/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            data: 'password',
            cost: 100,
            blockSize: 8,
            parallelization: 1,
            saltlen: 16,
            keylen: 32
        })
    });
    t.is(response.status, 200);
    const body = await response.json();
    t.truthy(body.error);
});
test.serial('HTTP /compare: verifies correct password', async (t) => {
    const hashResponse = await server.request('/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: 'testPassword', ...defaultParams })
    });
    const hashBody = await hashResponse.json();
    t.truthy(hashBody.result);
    const compareResponse = await server.request('/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: 'testPassword', hash: hashBody.result })
    });
    t.is(compareResponse.status, 200);
    const compareBody = await compareResponse.json();
    t.true(compareBody.result);
});
test.serial('HTTP /compare: rejects wrong password', async (t) => {
    const hashResponse = await server.request('/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: 'correctPassword', ...defaultParams })
    });
    const hashBody = await hashResponse.json();
    t.truthy(hashBody.result);
    const compareResponse = await server.request('/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: 'wrongPassword', hash: hashBody.result })
    });
    t.is(compareResponse.status, 200);
    const compareBody = await compareResponse.json();
    t.false(compareBody.result);
});
test.serial('HTTP /compare: error 400 without data', async (t) => {
    const response = await server.request('/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash: 'somehash' })
    });
    t.is(response.status, 400);
    const body = await response.json();
    t.truthy(body.error);
});
test.serial('HTTP /compare: error 400 without hash', async (t) => {
    const response = await server.request('/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: 'password' })
    });
    t.is(response.status, 400);
    const body = await response.json();
    t.truthy(body.error);
});
test.serial('HTTP /compare: error 400 with non-string data', async (t) => {
    const response = await server.request('/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: 123, hash: 'somehash' })
    });
    t.is(response.status, 400);
    const body = await response.json();
    t.truthy(body.error);
});
test.serial('HTTP /compare: error 400 with non-string hash', async (t) => {
    const response = await server.request('/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: 'password', hash: 123 })
    });
    t.is(response.status, 400);
    const body = await response.json();
    t.truthy(body.error);
});
test.serial('HTTP /compare: handles corrupted hash', async (t) => {
    const response = await server.request('/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: 'password', hash: 'notvalidbase64!!!' })
    });
    t.is(response.status, 200);
    const body = await response.json();
    t.truthy(body.error);
});
test.serial('HTTP /compare: error with malformed JSON', async (t) => {
    const response = await server.request('/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: 'invalid json {'
    });
    t.is(response.status, 400);
    const body = await response.json();
    t.truthy(body.error);
});
test.serial('HTTP /unknown: returns 404', async (t) => {
    const response = await server.request('/unknown', {
        method: 'GET'
    });
    t.is(response.status, 404);
    const body = await response.json();
    t.truthy(body.error);
});
test.serial('HTTP GET /hash: returns 404 (method not allowed)', async (t) => {
    const response = await server.request('/hash', {
        method: 'GET'
    });
    t.is(response.status, 404);
});
test.serial('Stop: server stops successfully', async (t) => {
    await t.notThrowsAsync(server.Stop());
});
