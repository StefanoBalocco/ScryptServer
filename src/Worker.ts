import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import workerpool from 'workerpool';

// Binary format v2:
// - 1 byte: binary version (0x02)
// - 1 byte: blockSize - 1 (4 bit, between 1 and 16) & parallelization - 1 (4 bit, between 1 and 16)
// - 1 byte: (log2 cost) - 12 (3 bit, between 12 and 19) & saltlen - 16 (5 bit, between 16 and 47)
// - 1 byte: keylen - 16 (between 16 and 271)
// - saltlen byte: salt
// - keylen byte: derived key
// Total: 4 + saltlen + keylen byte

const BINARY_VERSION = 0x02;

interface ScryptParams {
	cost: number,
	blockSize: number,
	parallelization: number,
	saltlen: number,
	keylen: number
}

function _hash( data: string, salt: Buffer, params: ScryptParams, version: number = BINARY_VERSION ): Buffer {
	let returnValue: Buffer;
	if( data && ( 0 < data.length ) && ( 2048 >= data.length ) ) {
		if( salt && ( params.saltlen === salt.length ) ) {
			let costMin: number;
			let costMax: number;
			let blockSizeMax: number;
			let parallelizationMax: number;
			let saltlenMax: number;
			let keylenMax: number;
			switch( version ) {
				case 0x01: {
					costMin = 1024;
					costMax = 65535;
					blockSizeMax = 15;
					parallelizationMax = 15;
					saltlenMax = 255;
					keylenMax = 255;
					break;
				}
				case 0x02: {
					costMin = 4096;
					costMax = 524288;
					blockSizeMax = 16;
					parallelizationMax = 16;
					saltlenMax = 47;
					keylenMax = 271;
					break;
				}
				default: {
					throw new Error( 'Unsupported binary version' );
				}
			}
			if( ( costMin <= params.cost ) && ( costMax >= params.cost ) ) {
				// Check if cost is a power of 2
				if( 0 === ( params.cost & ( params.cost - 1 ) ) ) {
					if( ( 1 <= params.blockSize ) && ( blockSizeMax >= params.blockSize ) ) {
						if( ( 1 <= params.parallelization ) && ( parallelizationMax >= params.parallelization ) ) {
							if( ( 16 <= params.saltlen ) && ( saltlenMax >= params.saltlen ) ) {
								if( ( 16 <= params.keylen ) && ( keylenMax >= params.keylen ) ) {
									try {
										const derivedKey: Buffer = scryptSync(
											data,
											salt,
											params.keylen,
											{
												cost: params.cost,
												blockSize: params.blockSize,
												parallelization: params.parallelization,
												maxmem: ( 128 * params.cost * params.blockSize * params.parallelization * 2 )
											}
										);
										if( derivedKey.length === params.keylen ) {
											let headerLength: number;
											switch( version ) {
												case 0x01: {
													headerLength = 6;
													returnValue = Buffer.allocUnsafe( headerLength + params.saltlen + params.keylen );
													returnValue.writeUInt8( version, 0 );
													returnValue.writeUInt16BE( params.cost, 1 );
													returnValue.writeUInt8( ( ( params.blockSize << 4 ) | params.parallelization ), 3 );
													returnValue.writeUInt8( params.saltlen, 4 );
													returnValue.writeUInt8( params.keylen, 5 );
													break;
												}
												case 0x02: {
													headerLength = 4;
													returnValue = Buffer.allocUnsafe( headerLength + params.saltlen + params.keylen );
													// binary version (1 byte)
													returnValue.writeUInt8( version, 0 );
													// blockSize (4 bit) & parallelization (4 bit) in 1 byte
													returnValue.writeUInt8( ( ( ( params.blockSize - 1 ) << 4 ) | ( params.parallelization - 1 ) ), 1 );
													//  (log2 cost) - 12 (3 bit) & saltlen - 16 (5 bit) in 1 byte
													returnValue.writeUInt8( ( ( Math.log2( params.cost ) - 12 ) << 5 | params.saltlen - 16 ), 2 );
													// keylen (1 byte)
													returnValue.writeUInt8( params.keylen - 16, 3 );
													break;
												}
											}
											// salt (saltlen byte)
											salt.copy( returnValue, headerLength );
											// hash (keylen byte)
											derivedKey.copy( returnValue, headerLength + params.saltlen );
										} else {
											throw new Error( 'Derived key length does not match keylen' );
										}
									} catch( error ) {
										throw ( error instanceof Error ? error : new Error( 'Derivation failed' ) );
									}
								} else {
									throw new Error( `Invalid keylen (16-${ keylenMax })` );
								}
							} else {
								throw new Error( `Invalid saltlen (16-${ saltlenMax })` );
							}
						} else {
							throw new Error( `Invalid parallelization parameter (1-${ parallelizationMax })` );
						}
					} else {
						throw new Error( `Invalid blockSize parameter (1-${ blockSizeMax })` );
					}
				} else {
					throw new Error( 'Invalid cost (not be a power of 2)' );
				}
			} else {
				throw new Error( `Invalid cost parameter (${ costMin }-${ costMax })` );
			}
		} else {
			throw new Error( 'Invalid salt length' );
		}
	} else {
		throw new Error( 'Missing, invalid or too much data' );
	}
	return returnValue;
}

function compare( data: string, hashBase64: string ): boolean {
	let returnValue: boolean = false;
	if( data && ( 0 < data.length ) && ( 2048 >= data.length ) ) {
		// Validate base64 format before attempting to decode
		if( /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test( hashBase64 ) ) {
			try {
				const hash: Buffer = Buffer.from( hashBase64, 'base64' );
				if( hash && 6 < hash.length ) {
					const version: number = hash.readUInt8( 0 );
					switch( version ) {
						case 0x01: {
							const saltlen: number = hash.readUInt8( 4 );
							const keylen: number = hash.readUInt8( 5 );
							const expectedLength: number = 6 + saltlen + keylen;
							if( expectedLength === hash.length ) {
								const blockSizeParallelization: number = hash.readUInt8( 3 );
								const derivedKey: Buffer = _hash(
									data,
									hash.subarray( 6, 6 + saltlen ),
									{
										cost: hash.readUInt16BE( 1 ),
										blockSize: blockSizeParallelization >> 4,
										parallelization: blockSizeParallelization & 0x0F,
										saltlen: saltlen,
										keylen: keylen
									},
									version
								);
								if( derivedKey.length === hash.length ) {
									returnValue = timingSafeEqual( derivedKey, hash );
								}
							} else {
								throw new Error( 'Invalid hash buffer length' );
							}
							break;
						}
						case 0x02: {
							const block2: number = hash.readUInt8( 2 );
							const saltlen: number = ( block2 & 0x1F ) + 16;
							const keylen: number = hash.readUInt8( 3 ) + 16;
							const expectedLength: number = 4 + saltlen + keylen;
							if( expectedLength === hash.length ) {
								const block1: number = hash.readUInt8( 1 );
								const derivedKey: Buffer = _hash(
									data,
									hash.subarray( 4, 4 + saltlen ),
									{
										cost: 2 ** ( ( block2 >> 5 ) + 12 ),
										blockSize: ( block1 >> 4 ) + 1,
										parallelization: ( block1 & 0x0F ) + 1,
										saltlen: saltlen,
										keylen: keylen
									},
									version
								);
								if( derivedKey.length === hash.length ) {
									returnValue = timingSafeEqual( derivedKey, hash );
								}
							} else {
								throw new Error( 'Invalid hash buffer length' );
							}
							break;
						}
						default: {
							throw new Error( 'Unsupported binary version' );
						}
					}
				} else {
					throw new Error( 'Missing or invalid hash buffer' );
				}
			} catch( error ) {
				throw ( error instanceof Error ? error : new Error( 'Derivation failed' ) );
			}
		} else {
			throw new Error( 'Missing or invalid hash' );
		}
	} else {
		throw new Error( 'Missing, invalid or too much data' );
	}
	return returnValue;
}

function hash( data: string, params: ScryptParams ): string {
	const salt: Buffer = randomBytes( params.saltlen );
	return _hash( data, salt, params, BINARY_VERSION ).toString( 'base64' );
}

workerpool.worker( {
	compare: compare,
	hash: hash
} );
