import { CpuInfo, cpus } from 'node:os';

const cores: CpuInfo[] = cpus();
const workers: number = ( ( 0 < cores.length ) ? cores.length : 1 );

type Undefinedable<T> = T | undefined;
export type Config = {
	minWorkers: number,
	maxWorkers: number,
	logpath: string,
	ip: string,
	port: number,
	certificate: Undefinedable<string>,
	certificateKey: Undefinedable<string>
};

export const DefaultConfig: Config = {
	minWorkers: Math.ceil( workers / 2 ),
	maxWorkers: workers,
	logpath: './log',
	ip: '127.0.0.1',
	port: 8001,
	certificate: undefined,
	certificateKey: undefined
};
