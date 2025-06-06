import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import workerpool from 'workerpool';
async function compare(data, hash) {
    let returnValue = false;
    if (data && (0 < data.length) && (2048 >= data.length)) {
        if (Buffer.isBuffer(hash) && 20 < hash.length) {
            const keylen = hash.readUInt8(3);
            const expectedLength = 20 + keylen;
            if (expectedLength === hash.length) {
                try {
                    const blockSizeParallelization = hash.readUInt8(2);
                    const cost = hash.readUInt16BE(0);
                    const blockSize = blockSizeParallelization >> 4;
                    const parallelization = blockSizeParallelization & 0x0F;
                    const salt = hash.subarray(4, 20);
                    const storedKey = hash.subarray(20);
                    const derivedKey = scryptSync(data, salt, keylen, {
                        cost: cost,
                        blockSize: blockSize,
                        parallelization: parallelization,
                        maxmem: (128 * cost * blockSize * parallelization * 2)
                    });
                    returnValue = timingSafeEqual(derivedKey, storedKey);
                }
                catch (error) {
                    throw (error instanceof Error ? error : new Error('Derivation failed'));
                }
            }
            else {
                throw new Error('Invalid hash buffer length');
            }
        }
        else {
            throw new Error('Missing or invalid hash buffer');
        }
    }
    else {
        throw new Error('Missing, invalid or too much data');
    }
    return returnValue;
}
async function hash(data, params) {
    let returnValue;
    if (data && (0 < data.length) && (2048 >= data.length)) {
        if ((1023 < params.cost) && (65537 > params.cost)) {
            if (0 === (params.cost & (params.cost - 1))) {
                if ((0 < params.blockSize) && (16 > params.blockSize)) {
                    if ((0 < params.parallelization) && (16 > params.parallelization)) {
                        if ((15 < params.keylen) && (256 > params.keylen)) {
                            try {
                                const salt = randomBytes(16);
                                const derivedKey = scryptSync(data, salt, params.keylen, {
                                    cost: params.cost,
                                    blockSize: params.blockSize,
                                    parallelization: params.parallelization,
                                    maxmem: (128 * params.cost * params.blockSize * params.parallelization * 2)
                                });
                                if (derivedKey.length === params.keylen) {
                                    returnValue = Buffer.allocUnsafe(20 + params.keylen);
                                    returnValue.writeUInt16BE(params.cost, 0);
                                    returnValue.writeUInt8((params.blockSize << 4) | params.parallelization, 2);
                                    returnValue.writeUInt8(params.keylen, 3);
                                    salt.copy(returnValue, 4);
                                    derivedKey.copy(returnValue, 20);
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
        throw new Error('Missing, invalid or too much data');
    }
    return returnValue;
}
workerpool.worker({
    compare: compare,
    hash: hash
});
