import test from 'ava';
import { createServer } from 'node:http';
const clientModule = await import('../../dist/ScryptClient.js');
const ScryptClient = clientModule.ScryptClient;
const defaultParams = {
    cost: 4096,
    blockSize: 8,
    parallelization: 1,
    saltlen: 16,
    keylen: 32
};
let httpServer;
let serverUrl;
function respondJson(response, statusCode, body) {
    response.writeHead(statusCode, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify(body));
}
test.before(async () => {
    httpServer = createServer((request, response) => {
        request.resume();
        request.on('end', () => {
            if (('POST' === request.method) && ('/hash' === request.url)) {
                respondJson(response, 200, { result: 'server-hash' });
            }
            else if (('POST' === request.method) && ('/compare' === request.url)) {
                respondJson(response, 200, { result: true });
            }
            else {
                respondJson(response, 404, { error: 'Not found' });
            }
        });
    });
    await new Promise((resolve) => {
        httpServer.listen(0, '127.0.0.1', resolve);
    });
    const address = httpServer.address();
    if (address && ('object' === typeof address)) {
        serverUrl = 'http://127.0.0.1:' + address.port;
    }
    else {
        throw new Error('http server did not bind to a TCP address');
    }
});
test.after.always(async () => {
    await new Promise((resolve, reject) => {
        httpServer.close((error) => {
            if (error) {
                reject(error);
            }
            else {
                resolve();
            }
        });
    });
});
test.serial('hash: returns result from live server endpoint', async (t) => {
    const client = new ScryptClient(serverUrl, defaultParams, undefined, 0);
    try {
        const result = await client.hash('password123');
        t.falsy(result.error);
        t.is(result.result, 'server-hash');
    }
    finally {
        await client.destroy();
    }
});
test.serial('compare: returns result from live server endpoint', async (t) => {
    const client = new ScryptClient(serverUrl, defaultParams, undefined, 0);
    try {
        const result = await client.compare('password123', 'somehash');
        t.falsy(result.error);
        t.true(result.result);
    }
    finally {
        await client.destroy();
    }
});
test.serial('compare: returns Service is currently offline after connection failure', async (t) => {
    const client = new ScryptClient('http://127.0.0.1:0', defaultParams, undefined, 0);
    try {
        const firstResult = await client.compare('password123', 'somehash');
        t.truthy(firstResult.error);
        const secondResult = await client.compare('password123', 'somehash');
        t.is(secondResult.error, 'Service is currently offline');
    }
    finally {
        await client.destroy();
    }
});
test.serial('hash: returns Service is currently offline after connection failure', async (t) => {
    const client = new ScryptClient('http://127.0.0.1:0', defaultParams, undefined, 0);
    try {
        const firstResult = await client.hash('password123');
        t.truthy(firstResult.error);
        const secondResult = await client.hash('password123');
        t.is(secondResult.error, 'Service is currently offline');
    }
    finally {
        await client.destroy();
    }
});
