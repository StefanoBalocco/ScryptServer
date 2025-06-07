import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import workerpool from 'workerpool';
const BINARY_VERSION = 0x01;
function _hash(data, salt, params) {
    let returnValue;
    if (data && (0 < data.length) && (2048 >= data.length)) {
        if (salt && (params.saltlen === salt.length)) {
            if ((1023 < params.cost) && (65537 > params.cost)) {
                if (0 === (params.cost & (params.cost - 1))) {
                    if ((0 < params.blockSize) && (16 > params.blockSize)) {
                        if ((0 < params.parallelization) && (16 > params.parallelization)) {
                            if ((15 < params.saltlen) && (256 > params.saltlen)) {
                                if ((15 < params.keylen) && (256 > params.keylen)) {
                                    try {
                                        const derivedKey = scryptSync(data, salt, params.keylen, {
                                            cost: params.cost,
                                            blockSize: params.blockSize,
                                            parallelization: params.parallelization,
                                            maxmem: (128 * params.cost * params.blockSize * params.parallelization * 2)
                                        });
                                        if (derivedKey.length === params.keylen) {
                                            returnValue = Buffer.allocUnsafe(6 + params.saltlen + params.keylen);
                                            returnValue.writeUInt8(BINARY_VERSION, 0);
                                            returnValue.writeUInt16BE(params.cost, 1);
                                            returnValue.writeUInt8((params.blockSize << 4) | params.parallelization, 3);
                                            returnValue.writeUInt8(params.saltlen, 4);
                                            returnValue.writeUInt8(params.keylen, 5);
                                            salt.copy(returnValue, 6);
                                            derivedKey.copy(returnValue, 6 + params.saltlen);
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
                                    throw new Error('Invalid keylen (16-255)');
                                }
                            }
                            else {
                                throw new Error('Invalid saltlen (16-255)');
                            }
                        }
                        else {
                            throw new Error('Invalid parallelization parameter (1-15)');
                        }
                    }
                    else {
                        throw new Error('Invalid blockSize parameter (1-15)');
                    }
                }
                else {
                    throw new Error('Invalid cost (not be a power of 2)');
                }
            }
            else {
                throw new Error('Invalid cost parameter (1024-65535)');
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
