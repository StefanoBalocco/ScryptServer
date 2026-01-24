type Undefinedable<T> = T | undefined;
export type Config = {
    minWorkers: number;
    maxWorkers: number;
    logpath: Undefinedable<string>;
    ip: string;
    port: number;
    certificate: Undefinedable<string>;
    certificateKey: Undefinedable<string>;
};
export declare const DefaultConfig: Config;
export {};
