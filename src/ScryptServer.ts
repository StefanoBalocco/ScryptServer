import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { createWriteStream } from 'node:fs';
import { Writable } from 'node:stream';
import { readFile } from 'node:fs/promises';
import { createServer as createHttpsServer } from 'node:https';
import path from 'path';
import workerpool from 'workerpool';
import ZeptoLogger from 'zeptologger';
import { Config, DefaultConfig } from './DefaultConfig.js';
import { ScryptParams } from './ScryptClient.js';

interface ScryptResponse<T> {
	error?: string;
	result?: T;
}

const _logger = ZeptoLogger.GetLogger();
_logger.minLevel = ZeptoLogger.LogLevel.INFO;

export class ScryptServer {
	private readonly _config: Config;
	private _workerPool: workerpool.Pool;
	private _app: Hono = new Hono();
	private _webserver: any;

	constructor( config: Config = DefaultConfig ) {
		this._config = config;
		this._logOpenStream();
		this._workerPool = workerpool.pool(
			path.join( import.meta.dirname, 'Worker.js' ),
			{
				minWorkers: this._config.minWorkers,
				maxWorkers: config.maxWorkers
			}
		);

		// 404 handler
		this._app.notFound(
			( context ) => {
				_logger.log( ZeptoLogger.LogLevel.ERROR, '404 Not found: ' + context.req.url );
				return context.json( { error: 'Not found' }, 404 );
			}
		);

		// Routes
		this._app.post(
			'/hash',
			async( context ) => {
				let returnValue: [ ScryptResponse<string>, ( 200 | 400 ) ] = [ {}, 200 ];
				try {
					const body = await context.req.json();
					if( body ) {
						if( 'string' === typeof body.data ) {
							if( Number.isInteger( body.cost ) && Number.isInteger( body.blockSize ) && Number.isInteger( body.parallelization ) && Number.isInteger( body.saltlen ) && Number.isInteger( body.keylen ) ) {
								returnValue[ 0 ] = await this.hash( body[ 'data' ], {
									cost: body.cost,
									blockSize: body.blockSize,
									parallelization: body.parallelization,
									saltlen: body.saltlen,
									keylen: body.keylen
								} );
							} else {
								returnValue[ 0 ].error = 'Invalid or missing params';
								returnValue[ 1 ] = 400;
							}
						} else {
							returnValue[ 0 ].error = 'Invalid or missing data';
							returnValue[ 1 ] = 400;
						}
					}

				} catch( error ) {
					returnValue[ 0 ].error = 'Invalid or missing data';
					returnValue[ 1 ] = 400;
					_logger.log( ZeptoLogger.LogLevel.ERROR, 'Error while processing hash request' + ( ( error instanceof Error ) ? ': ' + error.message : '' ) );
				}
				return context.json( returnValue[ 0 ], returnValue[ 1 ] );
			}
		);

		this._app.post(
			'/compare',
			async( context ) => {
				let returnValue: [ ScryptResponse<boolean>, ( 200 | 400 ) ] = [ {}, 200 ];
				try {
					const body = await context.req.json();
					if( body && ( 'string' === typeof body.data ) && ( 'string' === typeof body.hash ) ) {
						returnValue[ 0 ] = await this.compare( body[ 'data' ], body[ 'hash' ] );
					} else {
						returnValue[ 0 ].error = 'Invalid or missing data';
						returnValue[ 1 ] = 400;
					}
				} catch( error ) {
					returnValue[ 0 ].error = 'Invalid or missing data';
					returnValue[ 1 ] = 400;
					_logger.log( ZeptoLogger.LogLevel.ERROR, 'Error while processing compare request' + ( ( error instanceof Error ) ? ': ' + error.message : '' ) );
				}
				return context.json( returnValue[ 0 ], returnValue[ 1 ] );
			}
		);
	}

	public get request(): typeof this._app.request {
		return this._app.request.bind( this._app );
	}

	public async reloadCertificates(): Promise<void> {
		if( this._config.certificate && this._config.certificateKey && this._webserver ) {
			try {
				const certificate: Buffer = await readFile( this._config.certificate );
				if( certificate ) {
					const key: Buffer = await readFile( this._config.certificateKey );
					if( key ) {
						this._webserver.setSecureContext( { key: key, cert: certificate } );
						_logger.log( ZeptoLogger.LogLevel.INFO, 'Reloaded SSL certificates' );
					}
				}
			} catch( error ) {
				_logger.log( ZeptoLogger.LogLevel.ERROR, 'Error while reading SSL certificate or key' + ( ( error instanceof Error ) ? ': ' + error.message : '' ) );
			}
		}
	}

	public async compare( data: string, hash: string ): Promise<ScryptResponse<boolean>> {
		let returnValue: ScryptResponse<boolean> = {};
		try {
			returnValue.result = await this._workerPool.exec( 'compare', [ data, hash ] ) as boolean;
		} catch( error ) {
			returnValue.error = error instanceof Error ? error.message : 'internal error';
			_logger.log( ZeptoLogger.LogLevel.ERROR, error );
		}
		return returnValue;
	}

	public async hash( data: string, params: ScryptParams ): Promise<ScryptResponse<string>> {
		let returnValue: ScryptResponse<string> = {};
		try {
			returnValue.result = await this._workerPool.exec( 'hash', [ data, params ] ) as string;
		} catch( error ) {
			returnValue.error = error instanceof Error ? error.message : 'internal error';
			_logger.log( ZeptoLogger.LogLevel.ERROR, error );
		}
		return returnValue;
	}

	async Start(): Promise<void> {
		const server: {
			fetch: any,
			ip: string,
			port: number,
			createServer?: any,
			serverOptions?: any
		} = {
			fetch: this._app.fetch,
			ip: this._config.ip,
			port: this._config.port
		};
		if( this._config.certificate && this._config.certificateKey ) {
			try {
				const certificate: Buffer = await readFile( this._config.certificate );
				if( certificate && 0 < certificate.length ) {
					const certificateKey: Buffer = await readFile( this._config.certificateKey );
					if( certificateKey && 0 < certificateKey.length ) {
						server.createServer = createHttpsServer;
						server.serverOptions = {
							key: certificateKey,
							cert: certificate
						};
					}
				}
			} catch( error ) {
				_logger.log( ZeptoLogger.LogLevel.ERROR, 'Error while reading SSL certificate or key' + ( ( error instanceof Error ) ? ': ' + error.message : '' ) );
			}
		}
		this._webserver = serve( server );
		if( this._webserver ) {
			_logger.log( ZeptoLogger.LogLevel.NOTICE, `ScryptServer started on ${this._config.ip}:${this._config.port}` );
		} else {
			_logger.log( ZeptoLogger.LogLevel.CRITICAL, 'ScryptServer wasn\'t started' );
		}
	}

	public _logOpenStream(): void {
		let message: string = 'skipped';
		let destination: Writable = new Writable({ write( _, __, callback ) { callback(); }, writev( _, callback ) { callback(); } });
		if( this._config.logpath ) {
			message = 'opened';
			destination = createWriteStream( path.resolve( path.join( this._config.logpath, 'ScryptServer.log' ) ), { flags: 'a' } );
		}
		_logger.destination = destination;
		_logger.log( ZeptoLogger.LogLevel.INFO, 'Log file ' + message );
	}

	public async Stop(): Promise<void> {
		if( this._webserver ) {
			await new Promise<void>( ( resolve ) => {
				this._webserver.close( () => resolve() );
			} );
		}
		if( this._workerPool ) {
			await this._workerPool.terminate();
		}
		_logger.log( ZeptoLogger.LogLevel.NOTICE, 'ScryptServer stopped' );
	}
}
