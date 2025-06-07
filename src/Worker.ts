import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import workerpool from 'workerpool';

// Binary format:
// - 1 byte: binary version (0x01)
// - 2 byte: cost (uint16, big endian)
// - 1 byte: blockSize (4 bit) + parallelization (4 bit)
// - 1 byte: saltlen
// - 1 byte: keylen
// - saltlen byte: salt
// - keylen byte: derived key
// Total: 6 + saltlen + keylen byte

const BINARY_VERSION = 0x01;

interface ScryptParams {
	cost: number,
	blockSize: number,
	parallelization: number,
	saltlen: number,
	keylen: number
}

function _hash( data: string, salt: Buffer, params: ScryptParams ): Buffer {
	let returnValue: Buffer;
	if( data && ( 0 < data.length ) && ( 2048 >= data.length ) ) {
		if( salt && ( params.saltlen === salt.length ) ) {
			if( ( 1023 < params.cost ) && ( 65537 > params.cost ) ) {
				// Check if cost is a power of 2
				if( 0 === ( params.cost & ( params.cost - 1 ) ) ) {
					if( ( 0 < params.blockSize ) && ( 16 > params.blockSize ) ) {
						if( ( 0 < params.parallelization ) && ( 16 > params.parallelization ) ) {
							if( ( 15 < params.saltlen ) && ( 256 > params.saltlen ) ) {
								if( ( 15 < params.keylen ) && ( 256 > params.keylen ) ) {
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
											returnValue = Buffer.allocUnsafe( 6 + params.saltlen + params.keylen );
											// binary version (1 byte)
											returnValue.writeUInt8( BINARY_VERSION, 0 );
											// cost (2 byte, big endian)
											returnValue.writeUInt16BE( params.cost, 1 );
											// blockSize (4 bit) & parallelization (4 bit) in 1 byte
											returnValue.writeUInt8( ( params.blockSize << 4 ) | params.parallelization, 3 );
											// saltlen (1 byte)
											returnValue.writeUInt8( params.saltlen, 4 );
											// keylen (1 byte)
											returnValue.writeUInt8( params.keylen, 5 );
											// salt (saltlen byte)
											salt.copy( returnValue, 6 );
											// hash (keylen byte)
											derivedKey.copy( returnValue, 6 + params.saltlen );
										} else {
											throw new Error( 'Derived key length does not match keylen' );
										}
									} catch( error ) {
										throw ( error instanceof Error ? error : new Error( 'Derivation failed' ) );
									}
								} else {
									throw new Error( 'Invalid keylen (16-255)' );
								}
							} else {
								throw new Error( 'Invalid saltlen (16-255)' );
							}
						} else {
							throw new Error( 'Invalid parallelization parameter (1-15)' );
						}
					} else {
						throw new Error( 'Invalid blockSize parameter (1-15)' );
					}
				} else {
					throw new Error( 'Invalid cost (not be a power of 2)' );
				}
			} else {
				throw new Error( 'Invalid cost parameter (1024-65535)' );
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
		if( hashBase64 && ( 0 < hashBase64.length ) ) {
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
									}
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
			throw new Error( 'Missing or invalid hash data' );
		}
	} else {
		throw new Error( 'Missing, invalid or too much data' );
	}
	return returnValue;
}

function hash( data: string, params: ScryptParams ): string {
	const salt: Buffer = randomBytes( params.saltlen );
	return _hash( data, salt, params ).toString( 'base64' );
}

workerpool.worker( {
	compare: compare,
	hash: hash
} );
