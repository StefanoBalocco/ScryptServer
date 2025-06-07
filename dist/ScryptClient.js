import { cpus } from 'node:os';
import path from 'path';
import { Agent, request } from 'undici';
import workerpool from 'workerpool';
export class ScryptClient {
    _baseUrl;
    _backoffIncrement = 5000;
    _maxBackoff = 300000;
    _workerPool;
    _agent;
    _defaultParams;
    _consecutiveErrors = 0;
    _offlineUntil = 0;
    constructor(baseUrl, defaultParams = {}, cacert = undefined, maxConcurrencyFallback = -1) {
        this._baseUrl = baseUrl;
        this._defaultParams = {
            cost: defaultParams.cost ?? 16384,
            blockSize: defaultParams.blockSize ?? 8,
            parallelization: defaultParams.parallelization ?? 1,
            saltlen: defaultParams.saltlen ?? 16,
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
        if (-1 === maxConcurrencyFallback) {
            const cores = cpus();
            maxConcurrencyFallback = Math.ceil(((0 < cores.length) ? cores.length : 1) / 4);
        }
        if (0 < maxConcurrencyFallback) {
            this._workerPool = workerpool.pool(path.join(import.meta.dirname, 'Worker.js'), {
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
            saltlen: params?.saltlen ?? this._defaultParams.saltlen,
            keylen: params?.keylen ?? this._defaultParams.keylen
        };
        if (Date.now() > this._offlineUntil) {
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
                this._consecutiveErrors = 0;
                returnValue = await response.body.json();
            }
            catch (error) {
                returnValue.error = (error instanceof Error ? error.message : 'Unknown error');
                this._consecutiveErrors++;
                this._offlineUntil = Date.now() + Math.min(this._maxBackoff, this._consecutiveErrors * this._backoffIncrement);
            }
        }
        else {
            returnValue.error = 'Service is currently offline';
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
    async compare(data, hashBase64) {
        let returnValue = {};
        if (Date.now() > this._offlineUntil) {
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
                this._consecutiveErrors = 0;
                returnValue = await response.body.json();
            }
            catch (error) {
                returnValue.error = error instanceof Error ? error.message : 'unknown error';
                this._consecutiveErrors++;
                this._offlineUntil = Date.now() + Math.min(this._maxBackoff, this._consecutiveErrors * this._backoffIncrement);
            }
        }
        else {
            returnValue.error = 'Service is currently offline';
        }
        if (returnValue.error && this._workerPool) {
            returnValue = {};
            try {
                returnValue.result = await this._workerPool.exec('compare', [data, hashBase64]);
            }
            catch (error) {
                returnValue.error = error instanceof Error ? error.message : 'Unknown error';
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
