import path from 'path';
import { Agent, request } from 'undici';
import workerpool from 'workerpool';
export class ScryptClient {
    _baseUrl;
    _workerPool;
    _agent;
    _defaultParams;
    constructor(baseUrl, cacert = undefined, maxConcurrencyFallback = 2, defaultParams = {}) {
        this._baseUrl = baseUrl;
        this._defaultParams = {
            cost: defaultParams.cost ?? 16384,
            blockSize: defaultParams.blockSize ?? 8,
            parallelization: defaultParams.parallelization ?? 1,
            keylen: defaultParams.keylen ?? 32
        };
        const agentOptions = {
            connectTimeout: 2000,
            headersTimeout: 5000,
            bodyTimeout: 5000,
            keepAliveTimeout: 4000,
            keepAliveMaxTimeout: 10000,
            maxRedirections: 0,
            connect: {
                ca: cacert,
                rejectUnauthorized: true
            }
        };
        this._agent = new Agent(agentOptions);
        if (0 < maxConcurrencyFallback) {
            this._workerPool = workerpool.pool(path.join(__dirname, 'Worker.js'), {
                minWorkers: 0,
                maxWorkers: maxConcurrencyFallback,
                workerType: 'thread'
            });
        }
    }
    async hash(data, params) {
        let returnValue = {};
        const finalParams = {
            cost: params?.cost ?? this._defaultParams.cost,
            blockSize: params?.blockSize ?? this._defaultParams.blockSize,
            parallelization: params?.parallelization ?? this._defaultParams.parallelization,
            keylen: params?.keylen ?? this._defaultParams.keylen
        };
        try {
            const response = await request(this._baseUrl + '/hash', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept-Encoding': 'gzip, deflate'
                },
                body: JSON.stringify(Object.assign({ data: data }, finalParams)),
                dispatcher: this._agent
            });
            const jsonResponse = await response.body.json();
            returnValue.error = jsonResponse.error;
            returnValue.result = (jsonResponse.result ? Buffer.from(jsonResponse.result, 'base64') : undefined);
        }
        catch (error) {
            returnValue.error = error instanceof Error ? error.message : 'Unknown error';
        }
        if (returnValue.error && this._workerPool) {
            returnValue = {};
            try {
                returnValue.result = await this._workerPool.exec('hash', [data, finalParams]);
            }
            catch (error) {
                returnValue.error = error instanceof Error ? error.message : 'Unknown error';
            }
        }
        return returnValue;
    }
    async compare(data, hash) {
        return this.compareFromBase64(data, hash.toString('base64'));
    }
    async compareFromBase64(data, hashBase64) {
        let returnValue = {};
        try {
            const response = await request(this._baseUrl + '/compare', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept-Encoding': 'gzip, deflate'
                },
                body: JSON.stringify({
                    data: data,
                    hash: hashBase64
                }),
                dispatcher: this._agent
            });
            returnValue = await response.body.json();
        }
        catch (error) {
            returnValue.error = error instanceof Error ? error.message : 'unknown error';
        }
        if (returnValue.error && this._workerPool) {
            returnValue = {};
            try {
                const hashBuffer = Buffer.from(hashBase64, 'base64');
                returnValue.result = await this._workerPool.exec('compare', [data, hashBuffer]);
            }
            catch (error) {
                returnValue.error = error instanceof Error ? error.message : 'unknown error';
            }
        }
        return returnValue;
    }
    async destroy() {
        if (this._workerPool) {
            await this._workerPool.terminate();
        }
        await this._agent.destroy();
    }
}
