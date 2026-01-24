import { CpuInfo, cpus } from 'node:os';
import path from 'path';
import { Agent, Dispatcher, request } from 'undici';
import workerpool from 'workerpool';

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

export class ScryptClient {
	private readonly _baseUrl: string;
	private readonly _backoffIncrement: number = 5000; // 5 seconds
	private readonly _maxBackoff: number = 300000; // 5 minutes
	private _workerPool: Undefinedable<workerpool.Pool>;
	private _agent: Agent;
	private _defaultParams: ScryptParams;
	// Retry backoff state
	private _consecutiveErrors: number = 0;
	private _offlineUntil: number = 0;

	public constructor(
		baseUrl: string,
		defaultParams: Partial<ScryptParams> = {},
		cacert: Undefinedable<Buffer> = undefined,
		maxConcurrencyFallback: number = -1
	) {
		this._baseUrl = baseUrl;
		this._defaultParams = {
			cost: defaultParams.cost ?? 16384,
			blockSize: defaultParams.blockSize ?? 8,
			parallelization: defaultParams.parallelization ?? 1,
			saltlen: defaultParams.saltlen ?? 16,
			keylen: defaultParams.keylen ?? 32
		};
		const agentOptions: Agent.Options = {
			connectTimeout: 2000,
			headersTimeout: 5000,
			bodyTimeout: 5000,
			keepAliveTimeout: 4000,
			keepAliveMaxTimeout: 10000,
			connect: {
				ca: cacert,
				rejectUnauthorized: true
			}
		};
		this._agent = new Agent( agentOptions );
		if( -1 === maxConcurrencyFallback ) {
			const cores: CpuInfo[] = cpus();
			maxConcurrencyFallback = Math.ceil( ( ( 0 < cores.length ) ? cores.length : 1 ) / 4 );
		}
		if( 0 < maxConcurrencyFallback ) {
			this._workerPool = workerpool.pool(
				path.join( import.meta.dirname, 'Worker.js' ), {
					minWorkers: 0,
					maxWorkers: maxConcurrencyFallback,
					workerType: 'thread'
				}
			);
		}
	}

	public async hash( data: string, params?: Partial<ScryptParams> ): Promise<ScryptResponse<string>> {
		let returnValue: ScryptResponse<string> = {};
		const finalParams: ScryptParams = {
			cost: params?.cost ?? this._defaultParams.cost,
			blockSize: params?.blockSize ?? this._defaultParams.blockSize,
			parallelization: params?.parallelization ?? this._defaultParams.parallelization,
			saltlen: params?.saltlen ?? this._defaultParams.saltlen,
			keylen: params?.keylen ?? this._defaultParams.keylen
		};
		if( Date.now() > this._offlineUntil ) {
			try {
				const response: Dispatcher.ResponseData = await request(
					this._baseUrl + '/hash', {
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
							'Accept-Encoding': 'gzip, deflate'
						},
						body: JSON.stringify( Object.assign( { data: data }, finalParams ) ),
						dispatcher: this._agent
					}
				);
				this._consecutiveErrors = 0;
				returnValue = await response.body.json() as ScryptResponse<string>;
			} catch( error ) {
				returnValue.error = ( error instanceof Error ? error.message : 'Unknown error' );
				this._consecutiveErrors++;
				this._offlineUntil = Date.now() + Math.min( this._maxBackoff, this._consecutiveErrors * this._backoffIncrement );
			}
		} else {
			returnValue.error = 'Service is currently offline';
		}
		if( returnValue.error && this._workerPool ) {
			returnValue = {};
			try {
				returnValue.result = await this._workerPool.exec( 'hash', [ data, finalParams ] ) as string;
			} catch( error ) {
				returnValue.error = error instanceof Error ? error.message : 'Unknown error';
			}
		}
		return returnValue;
	}

	public async compare( data: string, hashBase64: string ): Promise<ScryptResponse<boolean>> {
		let returnValue: ScryptResponse<boolean> = {};
		if( Date.now() > this._offlineUntil ) {
			try {
				const response: Dispatcher.ResponseData = await request(
					this._baseUrl + '/compare', {
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
							'Accept-Encoding': 'gzip, deflate'
						},
						body: JSON.stringify( {
							data: data,
							hash: hashBase64
						} ),
						dispatcher: this._agent
					}
				);
				this._consecutiveErrors = 0;
				returnValue = await response.body.json() as ScryptResponse<boolean>;
			} catch( error ) {
				returnValue.error = error instanceof Error ? error.message : 'unknown error';
				this._consecutiveErrors++;
				this._offlineUntil = Date.now() + Math.min( this._maxBackoff, this._consecutiveErrors * this._backoffIncrement );
			}
		} else {
			returnValue.error = 'Service is currently offline';
		}
		// Local fallback
		if( returnValue.error && this._workerPool ) {
			returnValue = {};
			try {
				returnValue.result = await this._workerPool.exec( 'compare', [ data, hashBase64 ] ) as boolean;
			} catch( error ) {
				returnValue.error = error instanceof Error ? error.message : 'Unknown error';
			}
		}

		return returnValue;
	}

	public async destroy(): Promise<void> {
		if( this._workerPool ) {
			await this._workerPool.terminate();
		}
		await this._agent.destroy();
	}
}
