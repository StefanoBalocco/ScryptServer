import path from 'path';
const configModule = await import(path.join(import.meta.dirname, '..', '..', 'dist', 'DefaultConfig.js'));
const baseTestConfig = {
    minWorkers: 1,
    maxWorkers: 1,
    logpath: undefined,
    ip: '127.0.0.1',
    port: 8002,
    certificate: undefined,
    certificateKey: undefined
};
export function createTestConfig(overrides) {
    return { ...baseTestConfig, ...overrides };
}
