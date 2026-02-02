import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { createWriteStream } from 'node:fs';
import { Writable } from 'node:stream';
import { readFile } from 'node:fs/promises';
import { createServer as createHttpsServer } from 'node:https';
import path from 'path';
import workerpool from 'workerpool';
import ZeptoLogger from 'zeptologger';
import { DefaultConfig } from './DefaultConfig.js';
const _logger = ZeptoLogger.GetLogger();
_logger.minLevel = ZeptoLogger.LogLevel.INFO;
export class ScryptServer {
    _config;
    _workerPool;
    _app = new Hono();
    _webserver;
    constructor(config = DefaultConfig) {
        this._config = config;
        this._logOpenStream();
        this._workerPool = workerpool.pool(path.join(import.meta.dirname, 'Worker.js'), {
            minWorkers: this._config.minWorkers,
            maxWorkers: config.maxWorkers
        });
        this._app.notFound((context) => {
            _logger.log(ZeptoLogger.LogLevel.ERROR, '404 Not found: ' + context.req.url);
            return context.json({ error: 'Not found' }, 404);
        });
        this._app.post('/hash', async (context) => {
            let returnValue = [{}, 200];
            try {
                const body = await context.req.json();
                if (body) {
                    if ('string' === typeof body.data) {
                        if (Number.isInteger(body.cost) && Number.isInteger(body.blockSize) && Number.isInteger(body.parallelization) && Number.isInteger(body.saltlen) && Number.isInteger(body.keylen)) {
                            returnValue[0] = await this.hash(body['data'], {
                                cost: body.cost,
                                blockSize: body.blockSize,
                                parallelization: body.parallelization,
                                saltlen: body.saltlen,
                                keylen: body.keylen
                            });
                        }
                        else {
                            returnValue[0].error = 'Invalid or missing params';
                            returnValue[1] = 400;
                        }
                    }
                    else {
                        returnValue[0].error = 'Invalid or missing data';
                        returnValue[1] = 400;
                    }
                }
            }
            catch (error) {
                returnValue[0].error = 'Invalid or missing data';
                returnValue[1] = 400;
                _logger.log(ZeptoLogger.LogLevel.ERROR, 'Error while processing hash request' + ((error instanceof Error) ? ': ' + error.message : ''));
            }
            return context.json(returnValue[0], returnValue[1]);
        });
        this._app.post('/compare', async (context) => {
            let returnValue = [{}, 200];
            try {
                const body = await context.req.json();
                if (body && ('string' === typeof body.data) && ('string' === typeof body.hash)) {
                    returnValue[0] = await this.compare(body['data'], body['hash']);
                }
                else {
                    returnValue[0].error = 'Invalid or missing data';
                    returnValue[1] = 400;
                }
            }
            catch (error) {
                returnValue[0].error = 'Invalid or missing data';
                returnValue[1] = 400;
                _logger.log(ZeptoLogger.LogLevel.ERROR, 'Error while processing compare request' + ((error instanceof Error) ? ': ' + error.message : ''));
            }
            return context.json(returnValue[0], returnValue[1]);
        });
    }
    get request() {
        return this._app.request.bind(this._app);
    }
    async reloadCertificates() {
        if (this._config.certificate && this._config.certificateKey && this._webserver) {
            try {
                const certificate = await readFile(this._config.certificate);
                if (certificate) {
                    const key = await readFile(this._config.certificateKey);
                    if (key) {
                        this._webserver.setSecureContext({ key: key, cert: certificate });
                        _logger.log(ZeptoLogger.LogLevel.INFO, 'Reloaded SSL certificates');
                    }
                }
            }
            catch (error) {
                _logger.log(ZeptoLogger.LogLevel.ERROR, 'Error while reading SSL certificate or key' + ((error instanceof Error) ? ': ' + error.message : ''));
            }
        }
    }
    async compare(data, hash) {
        let returnValue = {};
        try {
            returnValue.result = await this._workerPool.exec('compare', [data, hash]);
        }
        catch (error) {
            returnValue.error = error instanceof Error ? error.message : 'internal error';
            _logger.log(ZeptoLogger.LogLevel.ERROR, error);
        }
        return returnValue;
    }
    async hash(data, params) {
        let returnValue = {};
        try {
            returnValue.result = await this._workerPool.exec('hash', [data, params]);
        }
        catch (error) {
            returnValue.error = error instanceof Error ? error.message : 'internal error';
            _logger.log(ZeptoLogger.LogLevel.ERROR, error);
        }
        return returnValue;
    }
    async Start() {
        const server = {
            fetch: this._app.fetch,
            hostname: this._config.ip,
            port: this._config.port
        };
        if (this._config.certificate && this._config.certificateKey) {
            try {
                const certificate = await readFile(this._config.certificate);
                if (certificate && 0 < certificate.length) {
                    const certificateKey = await readFile(this._config.certificateKey);
                    if (certificateKey && 0 < certificateKey.length) {
                        server.createServer = createHttpsServer;
                        server.serverOptions = {
                            key: certificateKey,
                            cert: certificate
                        };
                    }
                }
            }
            catch (error) {
                _logger.log(ZeptoLogger.LogLevel.ERROR, 'Error while reading SSL certificate or key' + ((error instanceof Error) ? ': ' + error.message : ''));
            }
        }
        this._webserver = serve(server);
        if (this._webserver) {
            _logger.log(ZeptoLogger.LogLevel.NOTICE, `ScryptServer started on ${this._config.ip}:${this._config.port}`);
        }
        else {
            _logger.log(ZeptoLogger.LogLevel.CRITICAL, 'ScryptServer wasn\'t started');
        }
    }
    _logOpenStream() {
        let message = 'skipped';
        let destination = new Writable({ write(_, __, callback) { callback(); }, writev(_, callback) { callback(); } });
        if (this._config.logpath) {
            message = 'opened';
            destination = createWriteStream(path.resolve(path.join(this._config.logpath, 'ScryptServer.log')), { flags: 'a' });
        }
        _logger.destination = destination;
        _logger.log(ZeptoLogger.LogLevel.INFO, 'Log file ' + message);
    }
    async Stop() {
        if (this._webserver) {
            await new Promise((resolve) => {
                this._webserver.close(() => resolve());
            });
        }
        if (this._workerPool) {
            await this._workerPool.terminate();
        }
        _logger.log(ZeptoLogger.LogLevel.NOTICE, 'ScryptServer stopped');
    }
}
