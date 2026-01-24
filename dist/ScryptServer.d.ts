import { Config } from './DefaultConfig.js';
import { ScryptParams } from './ScryptClient.js';
interface ScryptResponse<T> {
    error?: string;
    result?: T;
}
export declare class ScryptServer {
    private readonly _config;
    private _workerPool;
    private _app;
    private _webserver;
    constructor(config?: Config);
    get request(): typeof this._app.request;
    reloadCertificates(): Promise<void>;
    compare(data: string, hash: string): Promise<ScryptResponse<boolean>>;
    hash(data: string, params: ScryptParams): Promise<ScryptResponse<string>>;
    Start(): Promise<void>;
    _logOpenStream(): void;
    Stop(): Promise<void>;
}
export {};
