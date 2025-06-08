type Undefinedable<T> = T | undefined;
interface ScryptResponse<T> {
    error?: string;
    result?: T;
}
export interface ScryptParams {
    cost: number;
    blockSize: number;
    parallelization: number;
    saltlen: number;
    keylen: number;
}
export declare class ScryptClient {
    private readonly _baseUrl;
    private readonly _backoffIncrement;
    private readonly _maxBackoff;
    private _workerPool;
    private _agent;
    private _defaultParams;
    private _consecutiveErrors;
    private _offlineUntil;
    constructor(baseUrl: string, defaultParams?: Partial<ScryptParams>, cacert?: Undefinedable<Buffer>, maxConcurrencyFallback?: number);
    hash(data: string, params?: Partial<ScryptParams>): Promise<ScryptResponse<string>>;
    compare(data: string, hashBase64: string): Promise<ScryptResponse<boolean>>;
    destroy(): Promise<void>;
}
export {};
