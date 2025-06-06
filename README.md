# scryptServer

A microservice that exposes a scrypt API server to separate computationally expensive hashing from Node.js applications.

This package includes both a **server** component (ScryptServer) and a **client** library (ScryptClient) for easy integration.

## Server

### Starting the Server

```bash
# Build the TypeScript code
npm run build

# Start the server with default configuration
npm start

# Or start with a custom configuration file
npm start -- -c /path/to/config.json
# or
npm start -- --config /path/to/config.json
```

### Configuration

The server can be configured using a JSON configuration file. By default, it uses these settings:

```json
{
  "minWorkers": 2,          // Minimum number of worker threads (default: half of CPU cores)
  "maxWorkers": 4,          // Maximum number of worker threads (default: number of CPU cores)
  "logpath": "./log",       // Directory for log files
  "ip": "127.0.0.1",        // IP address to bind
  "port": 8001,             // Port to listen on
  "certificate": null,      // Path to SSL certificate file (optional)
  "certificateKey": null    // Path to SSL certificate key file (optional)
}
```

Create a custom configuration file and pass it with the `-c` or `--config` option to override any of these defaults.

### API Endpoints

#### HASH
POST `/hash`

Hashes data using scrypt with configurable parameters.

Request body (JSON):
- `data` (string, required): The data to hash (max 2048 characters)
- `cost` (number, required): CPU/memory cost parameter (must be power of 2, range: 1024-65535)
- `blockSize` (number, required): Block size parameter (range: 1-15)
- `parallelization` (number, required): Parallelization parameter (range: 1-15)
- `keylen` (number, required): Desired key length in bytes (range: 16-255)

Example request:
```json
{
  "data": "password123",
  "cost": 16384,
  "blockSize": 8,
  "parallelization": 1,
  "keylen": 32
}
```

Example response:
```json
{
  "result": "base64-encoded-hash"
}
```

#### COMPARE
POST `/compare`

Compares data against an existing scrypt hash.

Request body (JSON):
- `data` (string, required): The data to verify
- `hash` (string, required): The base64-encoded hash to compare against

Example request:
```json
{
  "data": "password123",
  "hash": "base64-encoded-hash"
}
```

Example response:
```json
{
  "result": true
}
```

### Binary Hash Format

The scrypt implementation uses a custom binary format:
- 2 bytes: cost (uint16, big endian)
- 1 byte: blockSize (4 bits) + parallelization (4 bits)
- 1 byte: keylen
- 16 bytes: salt
- keylen bytes: derived key
- Total: 20 + keylen bytes

### HTTPS Configuration

To enable HTTPS, configure the `certificate` and `certificateKey` paths in your configuration file:

```json
{
  "certificate": "/path/to/cert.pem",
  "certificateKey": "/path/to/key.pem"
}
```

### Logging and Signals

- Logs are written to `{logpath}/scryptServer.log`
- Send SIGHUP signal to reload SSL certificates and reopen log files without restarting

## Client

The package includes a TypeScript/JavaScript client library that provides:
- Easy integration with the scrypt server
- Automatic fallback to local scrypt computation if the server is unavailable
- Connection pooling with configurable timeouts
- Full TypeScript support

### Installation

```bash
npm install scryptserver
```

### Client Usage

```typescript
import { ScryptClient } from 'scryptserver';

// Initialize the client with default settings
const client = new ScryptClient('http://localhost:8001');

// Or with custom configuration
const client = new ScryptClient(
  'http://localhost:8001',     // Server URL
  undefined,                    // CA certificate buffer (for HTTPS)
  2,                           // Max local workers for fallback
  {                            // Default scrypt parameters
    cost: 16384,
    blockSize: 8,
    parallelization: 1,
    keylen: 32
  }
);

// Hash a password
const hashResult = await client.hash('myPassword');
if (hashResult.result) {
  console.log('Hash:', hashResult.result); // Buffer
  console.log('Base64:', hashResult.result.toString('base64'));
} else {
  console.error('Error:', hashResult.error);
}

// Hash with custom parameters
const customHashResult = await client.hash('myPassword', {
  cost: 32768,
  blockSize: 8,
  parallelization: 1,
  keylen: 64
});

// Compare a password (using Buffer)
const compareResult = await client.compare('myPassword', hashResult.result);
if (compareResult.result !== undefined) {
  console.log('Match:', compareResult.result); // boolean
} else {
  console.error('Error:', compareResult.error);
}

// Compare using base64 string
const compareBase64Result = await client.compareFromBase64(
  'myPassword', 
  hashResult.result.toString('base64')
);

// Clean up when done
await client.destroy();
```

### Client Configuration

The ScryptClient constructor accepts the following parameters:

- `baseUrl` (string): The URL of the scrypt server
- `cacert` (Buffer, optional): CA certificate for HTTPS connections
- `maxConcurrencyFallback` (number, default: -1): Maximum worker threads for local fallback
    - `-1`: Auto-detect (uses 1/4 of CPU cores, minimum 1)
    - `0`: Disable fallback completely
    - `> 0`: Use specified number of workers
- `defaultParams` (Partial<ScryptParams>, optional): Default scrypt parameters
    - `cost` (default: 16384): CPU/memory cost parameter
    - `blockSize` (default: 8): Block size parameter
    - `parallelization` (default: 1): Parallelization parameter
    - `keylen` (default: 32): Key length in bytes

### Connection Settings

The client uses the following connection timeouts:
- Connect timeout: 2000ms
- Headers timeout: 5000ms
- Body timeout: 5000ms
- Keep-alive timeout: 4000ms
- Keep-alive max timeout: 10000ms

### Fallback Mechanism

The client includes an automatic fallback mechanism:
- If the server is unavailable or returns an error, the client automatically computes the hash locally
- Local computation uses worker threads to avoid blocking the main thread
- The worker pool is created only if `maxConcurrencyFallback > 0`
- Set `maxConcurrencyFallback` to 0 to disable this feature

### Error Handling

Both hash and compare methods return an object with either:
- `result`: The successful result (Buffer for hash, boolean for compare)
- `error`: An error message if the operation failed

Always check for the presence of `error` before using `result`.

### Security Considerations

- Maximum input data length: 2048 characters
- Salt size: 128 bits (16 bytes)
- Cost parameter must be a power of 2
- All comparisons use timing-safe equality checks

---

Based on a my previous project (bcryptServer: https://github.com/stefanobalocco/bcryptServer).
