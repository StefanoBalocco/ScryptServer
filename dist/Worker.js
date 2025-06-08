import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import workerpool from 'workerpool';
const BINARY_VERSION = 0x02;
function _hash(data, salt, params) {
    let returnValue;
    if (data && (0 < data.length) && (2048 >= data.length)) {
        if (salt && (params.saltlen === salt.length)) {
            if ((4096 <= params.cost) && (524288 >= params.cost)) {
                if (0 === (params.cost & (params.cost - 1))) {
                    if ((1 <= params.blockSize) && (16 >= params.blockSize)) {
                        if ((1 <= params.parallelization) && (16 >= params.parallelization)) {
                            if ((16 <= params.saltlen) && (47 >= params.saltlen)) {
                                if ((16 <= params.keylen) && (271 >= params.keylen)) {
                                    try {
                                        const derivedKey = scryptSync(data, salt, params.keylen, {
                                            cost: params.cost,
                                            blockSize: params.blockSize,
                                            parallelization: params.parallelization,
                                            maxmem: (128 * params.cost * params.blockSize * params.parallelization * 2)
                                        });
                                        if (derivedKey.length === params.keylen) {
                                            returnValue = Buffer.allocUnsafe(4 + params.saltlen + params.keylen);
                                            returnValue.writeUInt8(BINARY_VERSION, 0);
                                            returnValue.writeUInt8((((params.blockSize - 1) << 4) | (params.parallelization - 1)), 1);
                                            returnValue.writeUInt8(((Math.log2(params.cost) - 12) << 5 | params.saltlen - 16), 2);
                                            returnValue.writeUInt8(params.keylen - 16, 3);
                                            salt.copy(returnValue, 4);
                                            derivedKey.copy(returnValue, 4 + params.saltlen);
                                        }
                                        else {
                                            throw new Error('Derived key length does not match keylen');
                                        }
                                    }
                                    catch (error) {
                                        throw (error instanceof Error ? error : new Error('Derivation failed'));
                                    }
                                }
                                else {
                                    throw new Error('Invalid keylen (16-271)');
                                }
                            }
                            else {
                                throw new Error('Invalid saltlen (16-47)');
                            }
                        }
                        else {
                            throw new Error('Invalid parallelization parameter (1-16)');
                        }
                    }
                    else {
                        throw new Error('Invalid blockSize parameter (1-16)');
                    }
                }
                else {
                    throw new Error('Invalid cost (not be a power of 2)');
                }
            }
            else {
                throw new Error('Invalid cost parameter (4096-524288)');
            }
        }
        else {
            throw new Error('Invalid salt length');
        }
    }
    else {
        throw new Error('Missing, invalid or too much data');
    }
    return returnValue;
}
function compare(data, hashBase64) {
    let returnValue = false;
    if (data && (0 < data.length) && (2048 >= data.length)) {
        if (hashBase64 && (0 < hashBase64.length)) {
            try {
                const hash = Buffer.from(hashBase64, 'base64');
                if (hash && 6 < hash.length) {
                    const version = hash.readUInt8(0);
                    switch (version) {
                        case 0x01: {
                            const saltlen = hash.readUInt8(4);
                            const keylen = hash.readUInt8(5);
                            const expectedLength = 6 + saltlen + keylen;
                            if (expectedLength === hash.length) {
                                const blockSizeParallelization = hash.readUInt8(3);
                                const derivedKey = _hash(data, hash.subarray(6, 6 + saltlen), {
                                    cost: hash.readUInt16BE(1),
                                    blockSize: blockSizeParallelization >> 4,
                                    parallelization: blockSizeParallelization & 0x0F,
                                    saltlen: saltlen,
                                    keylen: keylen
                                });
                                if (derivedKey.length === hash.length) {
                                    returnValue = timingSafeEqual(derivedKey, hash);
                                }
                            }
                            else {
                                throw new Error('Invalid hash buffer length');
                            }
                            break;
                        }
                        case 0x02: {
                            const block2 = hash.readUInt8(2);
                            const saltlen = (block2 & 0x1F) + 16;
                            const keylen = hash.readUInt8(3) + 16;
                            const expectedLength = 4 + saltlen + keylen;
                            if (expectedLength === hash.length) {
                                const block1 = hash.readUInt8(1);
                                const derivedKey = _hash(data, hash.subarray(4, 4 + saltlen), {
                                    cost: 2 ** ((block2 >> 5) + 12),
                                    blockSize: (block1 >> 4) + 1,
                                    parallelization: (block1 & 0x0F) + 1,
                                    saltlen: saltlen,
                                    keylen: keylen
                                });
                                if (derivedKey.length === hash.length) {
                                    returnValue = timingSafeEqual(derivedKey, hash);
                                }
                            }
                            else {
                                throw new Error('Invalid hash buffer length');
                            }
                            break;
                        }
                        default: {
                            throw new Error('Unsupported binary version');
                        }
                    }
                }
                else {
                    throw new Error('Missing or invalid hash buffer');
                }
            }
            catch (error) {
                throw (error instanceof Error ? error : new Error('Derivation failed'));
            }
        }
        else {
            throw new Error('Missing or invalid hash data');
        }
    }
    else {
        throw new Error('Missing, invalid or too much data');
    }
    return returnValue;
}
function hash(data, params) {
    const salt = randomBytes(params.saltlen);
    return _hash(data, salt, params).toString('base64');
}
workerpool.worker({
    compare: compare,
    hash: hash
});
