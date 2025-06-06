import path from 'path';
import { Agent, Dispatcher, request } from 'undici';
import workerpool from 'workerpool';

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

export class ScryptClient {
	private readonly _baseUrl: string;
	private _workerPool: Undefinedable<workerpool.Pool>;
	private _agent: Agent;
	private _defaultParams: ScryptParams;

	public constructor(
		baseUrl: string,
		cacert: Undefinedable<Buffer> = undefined,
		maxConcurrencyFallback: number = 2,
		defaultParams: Partial<ScryptParams> = {}
	) {
		this._baseUrl = baseUrl;
		this._defaultParams = {
			cost: defaultParams.cost ?? 16384,
			blockSize: defaultParams.blockSize ?? 8,
			parallelization: defaultParams.parallelization ?? 1,
			keylen: defaultParams.keylen ?? 32
		};
		const agentOptions: Agent.Options = {
			connectTimeout: 2000,
			headersTimeout: 5000,
			bodyTimeout: 5000,
			keepAliveTimeout: 4000,
			keepAliveMaxTimeout: 10000,
			maxRedirections: 0,
			connect: {
				ca: cacert,
				rejectUnauthorized: true
			}
		};
		this._agent = new Agent( agentOptions );
		if( 0 < maxConcurrencyFallback ) {
			this._workerPool = workerpool.pool(
				path.join( __dirname, 'Worker.js' ), {
					minWorkers: 0,
					maxWorkers: maxConcurrencyFallback,
					workerType: 'thread'
				}
			);
		}
	}

	public async hash( data: string, params?: Partial<ScryptParams> ): Promise<scryptResponse<Buffer>> {
		let returnValue: scryptResponse<Buffer> = {};
		const finalParams: ScryptParams = {
			cost: params?.cost ?? this._defaultParams.cost,
			blockSize: params?.blockSize ?? this._defaultParams.blockSize,
			parallelization: params?.parallelization ?? this._defaultParams.parallelization,
			keylen: params?.keylen ?? this._defaultParams.keylen
		};
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
			const jsonResponse = await response.body.json() as scryptResponse<string>;
			returnValue.error = jsonResponse.error;
			returnValue.result = ( jsonResponse.result ? Buffer.from( jsonResponse.result, 'base64' ) : undefined );
		} catch( error ) {
			returnValue.error = error instanceof Error ? error.message : 'Unknown error';
		}

		if( returnValue.error && this._workerPool ) {
			returnValue = {};
			try {
				returnValue.result = await this._workerPool.exec( 'hash', [ data, finalParams ] ) as Buffer;
			} catch( error ) {
				returnValue.error = error instanceof Error ? error.message : 'Unknown error';
			}
		}

		return returnValue;
	}

	public async compare( data: string, hash: Buffer ): Promise<scryptResponse<boolean>> {
		return this.compareFromBase64( data, hash.toString( 'base64' ) );
	}

	public async compareFromBase64( data: string, hashBase64: string ): Promise<scryptResponse<boolean>> {
		let returnValue: scryptResponse<boolean> = {};

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
			returnValue = await response.body.json() as scryptResponse<boolean>;
		} catch( error ) {
			returnValue.error = error instanceof Error ? error.message : 'unknown error';
		}

		// Local fallback
		if( returnValue.error && this._workerPool ) {
			returnValue = {};
			try {
				const hashBuffer = Buffer.from( hashBase64, 'base64' );
				returnValue.result = await this._workerPool.exec( 'compare', [ data, hashBuffer ] ) as boolean;
			} catch( error ) {
				returnValue.error = error instanceof Error ? error.message : 'unknown error';
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
