import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import workerpool from 'workerpool';
const BINARY_VERSION = 0x02;
function _hash(data, salt, params, version = BINARY_VERSION) {
    let returnValue;
    if (data && (0 < data.length) && (2048 >= data.length)) {
        if (salt && (params.saltlen === salt.length)) {
            let costMin;
            let costMax;
            let blockSizeMax;
            let parallelizationMax;
            let saltlenMax;
            let keylenMax;
            switch (version) {
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
                    throw new Error('Unsupported binary version');
                }
            }
            if ((costMin <= params.cost) && (costMax >= params.cost)) {
                if (0 === (params.cost & (params.cost - 1))) {
                    if ((1 <= params.blockSize) && (blockSizeMax >= params.blockSize)) {
                        if ((1 <= params.parallelization) && (parallelizationMax >= params.parallelization)) {
                            if ((16 <= params.saltlen) && (saltlenMax >= params.saltlen)) {
                                if ((16 <= params.keylen) && (keylenMax >= params.keylen)) {
                                    try {
                                        const derivedKey = scryptSync(data, salt, params.keylen, {
                                            cost: params.cost,
                                            blockSize: params.blockSize,
                                            parallelization: params.parallelization,
                                            maxmem: (128 * params.cost * params.blockSize * params.parallelization * 2)
                                        });
                                        if (derivedKey.length === params.keylen) {
                                            let headerLength;
                                            switch (version) {
                                                case 0x01: {
                                                    headerLength = 6;
                                                    returnValue = Buffer.allocUnsafe(headerLength + params.saltlen + params.keylen);
                                                    returnValue.writeUInt8(version, 0);
                                                    returnValue.writeUInt16BE(params.cost, 1);
                                                    returnValue.writeUInt8(((params.blockSize << 4) | params.parallelization), 3);
                                                    returnValue.writeUInt8(params.saltlen, 4);
                                                    returnValue.writeUInt8(params.keylen, 5);
                                                    break;
                                                }
                                                case 0x02: {
                                                    headerLength = 4;
                                                    returnValue = Buffer.allocUnsafe(headerLength + params.saltlen + params.keylen);
                                                    returnValue.writeUInt8(version, 0);
                                                    returnValue.writeUInt8((((params.blockSize - 1) << 4) | (params.parallelization - 1)), 1);
                                                    returnValue.writeUInt8(((Math.log2(params.cost) - 12) << 5 | params.saltlen - 16), 2);
                                                    returnValue.writeUInt8(params.keylen - 16, 3);
                                                    break;
                                                }
                                            }
                                            salt.copy(returnValue, headerLength);
                                            derivedKey.copy(returnValue, headerLength + params.saltlen);
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
                                    throw new Error(`Invalid keylen (16-${keylenMax})`);
                                }
                            }
                            else {
                                throw new Error(`Invalid saltlen (16-${saltlenMax})`);
                            }
                        }
                        else {
                            throw new Error(`Invalid parallelization parameter (1-${parallelizationMax})`);
                        }
                    }
                    else {
                        throw new Error(`Invalid blockSize parameter (1-${blockSizeMax})`);
                    }
                }
                else {
                    throw new Error('Invalid cost (not be a power of 2)');
                }
            }
            else {
                throw new Error(`Invalid cost parameter (${costMin}-${costMax})`);
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
        if (/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(hashBase64)) {
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
                                }, version);
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
                                }, version);
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
            throw new Error('Missing or invalid hash');
        }
    }
    else {
        throw new Error('Missing, invalid or too much data');
    }
    return returnValue;
}
function hash(data, params) {
    const salt = randomBytes(params.saltlen);
    return _hash(data, salt, params, BINARY_VERSION).toString('base64');
}
workerpool.worker({
    compare: compare,
    hash: hash
});
//# sourceMappingURL=Worker.js.map