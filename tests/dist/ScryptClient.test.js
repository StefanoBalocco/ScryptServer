import test from 'ava';
import path from 'path';
const clientModule = await import(path.join(import.meta.dirname, '..', '..', 'dist', 'ScryptClient.js'));
const ScryptClient = clientModule.ScryptClient;
const defaultParams = {
    cost: 4096,
    blockSize: 8,
    parallelization: 1,
    saltlen: 16,
    keylen: 32
};
let client;
test.before(() => {
    client = new ScryptClient('http://127.0.0.1:59999', defaultParams, undefined, 2);
});
test.after.always(async () => {
    await client.destroy();
});
test.serial('hash fallback: generates hash when server unavailable', async (t) => {
    const result = await client.hash('password123');
    t.falsy(result.error);
    t.truthy(result.result);
    t.is(typeof result.result, 'string');
});
test.serial('hash fallback: uses default params', async (t) => {
    const result = await client.hash('password');
    t.falsy(result.error);
    t.truthy(result.result);
    const buffer = Buffer.from(result.result, 'base64');
    t.is(buffer[0], 0x02);
});
test.serial('hash fallback: uses custom params', async (t) => {
    const customParams = {
        cost: 8192,
        blockSize: 4,
        parallelization: 2,
        saltlen: 24,
        keylen: 48
    };
    const result = await client.hash('password', customParams);
    t.falsy(result.error);
    t.truthy(result.result);
    const buffer = Buffer.from(result.result, 'base64');
    t.is(buffer.length, 4 + customParams.saltlen + customParams.keylen);
});
test.serial('hash fallback: partial params override', async (t) => {
    const result = await client.hash('password', { cost: 8192 });
    t.falsy(result.error);
    t.truthy(result.result);
});
test.serial('hash fallback: error with invalid params', async (t) => {
    const result = await client.hash('password', { cost: 100 });
    t.truthy(result.error);
    t.falsy(result.result);
});
test.serial('hash fallback: error with empty data', async (t) => {
    const result = await client.hash('');
    t.truthy(result.error);
    t.falsy(result.result);
});
test.serial('compare fallback: verifies correct password', async (t) => {
    const password = 'myPassword123';
    const hashResult = await client.hash(password);
    t.falsy(hashResult.error);
    const compareResult = await client.compare(password, hashResult.result);
    t.falsy(compareResult.error);
    t.true(compareResult.result);
});
test.serial('compare fallback: rejects wrong password', async (t) => {
    const hashResult = await client.hash('correctPassword');
    t.falsy(hashResult.error);
    const compareResult = await client.compare('wrongPassword', hashResult.result);
    t.falsy(compareResult.error);
    t.false(compareResult.result);
});
test.serial('compare fallback: error with invalid hash', async (t) => {
    const result = await client.compare('password', 'invalid-hash');
    t.truthy(result.error);
});
test.serial('compare fallback: error with empty data', async (t) => {
    const hashResult = await client.hash('password');
    const result = await client.compare('', hashResult.result);
    t.truthy(result.error);
});
test('constructor: uses default params when not specified', async (t) => {
    const clientDefault = new ScryptClient('http://127.0.0.1:59998');
    const result = await clientDefault.hash('test');
    t.falsy(result.error);
    t.truthy(result.result);
    const buffer = Buffer.from(result.result, 'base64');
    t.is(buffer.length, 52);
    await clientDefault.destroy();
});
test('constructor: merges partial default params', async (t) => {
    const clientPartial = new ScryptClient('http://127.0.0.1:59997', { cost: 8192 });
    const result = await clientPartial.hash('test');
    t.falsy(result.error);
    t.truthy(result.result);
    await clientPartial.destroy();
});
test('no fallback: returns error when server unavailable', async (t) => {
    const clientNoFallback = new ScryptClient('http://127.0.0.1:59996', defaultParams, undefined, 0);
    const result = await clientNoFallback.hash('password');
    t.truthy(result.error);
    t.falsy(result.result);
    await clientNoFallback.destroy();
});
test('destroy: terminates correctly', async (t) => {
    const tempClient = new ScryptClient('http://127.0.0.1:59995');
    await t.notThrowsAsync(() => tempClient.destroy());
});
test.serial('concurrency fallback: handles parallel requests', async (t) => {
    const passwords = ['pass1', 'pass2', 'pass3', 'pass4'];
    const promises = passwords.map(p => client.hash(p));
    const results = await Promise.all(promises);
    for (const result of results) {
        t.falsy(result.error);
        t.truthy(result.result);
    }
});
