type Undefinedable<T> = T | undefined;
interface scryptResponse<T> {
    error?: string;
    result?: T;
}
interface ScryptParams {
    cost: number;
    blockSize: number;
    parallelization: number;
    keylen: number;
}
export declare class ScryptClient {
    private readonly _baseUrl;
    private _workerPool;
    private _agent;
    private _defaultParams;
    constructor(baseUrl: string, cacert?: Undefinedable<Buffer>, maxConcurrencyFallback?: number, defaultParams?: Partial<ScryptParams>);
    hash(data: string, params?: Partial<ScryptParams>): Promise<scryptResponse<Buffer>>;
    compare(data: string, hash: Buffer): Promise<scryptResponse<boolean>>;
    compareFromBase64(data: string, hashBase64: string): Promise<scryptResponse<boolean>>;
    destroy(): Promise<void>;
}
export {};
