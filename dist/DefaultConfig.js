import { cpus } from 'node:os';
const cores = cpus();
const workers = ((0 < cores.length) ? cores.length : 1);
export const DefaultConfig = {
    minWorkers: Math.ceil(workers / 2),
    maxWorkers: workers,
    logpath: './log',
    ip: '127.0.0.1',
    port: 8001,
    certificate: undefined,
    certificateKey: undefined
};
