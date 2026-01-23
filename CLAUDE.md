# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Run Commands

```bash
# Build TypeScript
npm run build

# Start server (default config)
npm start

# Start server with custom config
npm start -- -c /path/to/config.json
```

## Architecture

ScryptServer is a microservice that offloads scrypt hashing from Node.js applications. It provides both a server component and a client library.

### Components

- **ScryptServer** (`src/ScryptServer.ts`): Hono-based HTTP server that handles `/hash` and `/compare` endpoints. Uses a workerpool for CPU-intensive scrypt operations. Supports HTTPS and log file rotation via SIGHUP.

- **ScryptClient** (`src/ScryptClient.ts`): HTTP client with automatic fallback to local computation if server is unavailable. Implements exponential backoff (5s increments, max 5 minutes) when server fails.

- **Worker** (`src/Worker.ts`): Workerpool worker that performs actual scrypt operations using Node's crypto module. Contains the binary format encoding/decoding logic.

- **DefaultConfig** (`src/DefaultConfig.ts`): Server configuration with auto-detected worker counts based on CPU cores.

### Binary Hash Format (v2)

The hash output uses a compact binary format:
- Byte 0: Version (0x02)
- Byte 1: blockSize-1 (4 bits) | parallelization-1 (4 bits)
- Byte 2: (log2(cost)-12) (3 bits) | saltlen-16 (5 bits)
- Byte 3: keylen-16
- Bytes 4 to 4+saltlen: salt
- Remaining: derived key

Version 1 (0x01) is still supported for backward compatibility during compare operations.

### Parameter Constraints

- cost: 4096-524288 (must be power of 2)
- blockSize: 1-16
- parallelization: 1-16
- saltlen: 16-47
- keylen: 16-271
- data: max 2048 characters

### Key Design Decisions

- Client fallback uses local workerpool with 1/4 of CPU cores (configurable)
- Server workerpool uses half to full CPU cores
- All hash results are base64 encoded strings
- timingSafeEqual used for hash comparison to prevent timing attacks
