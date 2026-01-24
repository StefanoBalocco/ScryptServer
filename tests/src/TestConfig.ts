import path from 'path';

const configModule = await import( path.join( import.meta.dirname, '..', '..', 'dist', 'DefaultConfig.js' ) );
type Config = typeof configModule.DefaultConfig;

const baseTestConfig: Config = {
	minWorkers: 1,
	maxWorkers: 1,
	logpath: undefined,
	ip: '127.0.0.1',
	port: 8002,
	certificate: undefined,
	certificateKey: undefined
};

export function createTestConfig( overrides?: Partial<Config> ): Config {
	return { ...baseTestConfig, ...overrides };
}
