'use strict';

/**
 * stream-proxy.js  –  ResearchChatAI
 *
 * Lightweight Node.js streaming proxy (zero dependencies beyond Node stdlib).
 *
 * Architecture (three-phase streaming):
 *   1. prepareChat.php  → saves participant message, writes AI request config
 *                         to a temp file, returns a one-time 64-char hex token.
 *   2. stream-proxy.js  → reads that config, opens a streaming connection to
 *                         the AI provider, pipes raw SSE bytes to the browser.
 *                         THIS FILE.
 *   3. saveResponse.php → frontend POSTs the accumulated response to persist it.
 *
 * Security:
 *   - API keys are never sent by the browser; they live in the temp config file.
 *   - Config files are read-once (deleted immediately after reading).
 *   - Tokens are validated: 64-char hex, max age, one-time use.
 *   - Upstream URLs are validated: HTTPS only, no internal/private IPs.
 *   - Request body size is capped (1 KB — only a token is expected).
 *   - Stale config files are auto-cleaned every 60 seconds.
 *
 * Configuration (all via environment variables):
 *   STREAM_PROXY_PORT    – listen port          (default: 9222)
 *   STREAM_PROXY_HOST    – listen host          (default: 0.0.0.0)
 *   STREAM_CONFIG_DIR    – temp config dir      (default: /tmp/rcai_stream_configs)
 *   STREAM_TOKEN_MAX_AGE – max token age in s   (default: 120)
 *   STREAM_CORS_ORIGINS  – allowed origins CSV  (default: *)
 *
 * Usage:
 *   node stream-proxy.js
 *   STREAM_PROXY_PORT=9333 node stream-proxy.js
 * 
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
 * License: MIT
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const net = require('net');

/* ------------------------------------------------------------------
 *  Configuration  (override with env vars)
 * ------------------------------------------------------------------ */
const PORT = parseInt(process.env.STREAM_PROXY_PORT || '9222', 10);
const HOST = process.env.STREAM_PROXY_HOST || '0.0.0.0';
const CONFIG_DIR = process.env.STREAM_CONFIG_DIR;
const MAX_TOKEN_AGE_S = parseInt(process.env.STREAM_TOKEN_MAX_AGE || '120', 10);
const ALLOWED_ORIGINS = process.env.STREAM_CORS_ORIGINS || '*';

/** Maximum POST body size (bytes). Only a JSON token is expected, so 1 KB is generous. */
const MAX_BODY_SIZE = 1024;

/* ------------------------------------------------------------------
 *  Structured logger  (JSON to stdout/stderr, easy to parse)
 * ------------------------------------------------------------------ */
function log(level, msg, meta = {}) {
    const entry = { ts: new Date().toISOString(), level, msg, ...meta };
    const out = level === 'error' || level === 'warn' ? process.stderr : process.stdout;
    out.write(JSON.stringify(entry) + '\n');
}

/* ------------------------------------------------------------------
 *  Active connection tracking  (for health check & graceful shutdown)
 * ------------------------------------------------------------------ */
let activeStreams = 0;

/* ------------------------------------------------------------------
 *  HTTP Server
 * ------------------------------------------------------------------ */
const server = http.createServer((req, res) => {

    // ---- CORS ----
    const origin = req.headers.origin || '*';
    const corsOrigin = ALLOWED_ORIGINS === '*' ? '*' : (
        ALLOWED_ORIGINS.split(',').map(s => s.trim()).includes(origin) ? origin : 'null'
    );
    res.setHeader('Access-Control-Allow-Origin', corsOrigin);
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');

    // ---- CORS preflight ----
    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    // ---- Health check (GET) – for monitoring / supervisord ----
    if (req.method === 'GET' && req.url.endsWith('/health')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            ok: true,
            activeStreams,
            uptime: Math.round(process.uptime()),
        }));
        return;
    }

    // ---- Only accept POST to the stream endpoint ----
    // Server forwards the full URL path (e.g. /ResearchChat/Backend/Chat/stream)
    if (req.method !== 'POST' || !req.url.endsWith('/stream')) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
        return;
    }

    // ---- Read POST body with size limit ----
    let body = '';
    let overflow = false;

    req.on('data', (chunk) => {
        body += chunk;
        if (body.length > MAX_BODY_SIZE) {
            overflow = true;
            req.destroy();
        }
    });

    req.on('end', () => {
        if (overflow) {
            res.writeHead(413, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Request body too large' }));
            return;
        }

        // ---- Parse token ----
        let token;
        try {
            // Accept both JSON body and form-encoded
            if (body.startsWith('{')) {
                token = JSON.parse(body).requestToken;
            } else {
                token = new URLSearchParams(body).get('requestToken');
            }
        } catch (e) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid request body' }));
            return;
        }

        // Token must be exactly 64 hex chars (output of bin2hex(random_bytes(32)))
        if (!token || !/^[a-f0-9]{64}$/.test(token)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid or missing requestToken' }));
            return;
        }

        // ---- Read & delete the one-time config file ----
        const configPath = path.join(CONFIG_DIR, token + '.json');

        let configRaw;
        try {
            configRaw = fs.readFileSync(configPath, 'utf8');
            fs.unlinkSync(configPath); // one-time use: delete immediately
        } catch (e) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Token not found or already used' }));
            return;
        }

        let config;
        try {
            config = JSON.parse(configRaw);
        } catch (e) {
            log('error', 'Corrupt config file', { token: token.slice(0, 8) + '...' });
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Corrupt config file' }));
            return;
        }

        // ---- Expiry check ----
        if (config.createdAt && (Date.now() / 1000 - config.createdAt) > MAX_TOKEN_AGE_S) {
            log('warn', 'Token expired', { ageS: Math.round(Date.now() / 1000 - config.createdAt) });
            res.writeHead(410, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Token expired' }));
            return;
        }

        // ---- Validate upstream URL (SSRF protection) ----
        if (!isAllowedUpstreamUrl(config.url)) {
            log('error', 'Blocked upstream URL', { url: config.url });
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Upstream URL not allowed' }));
            return;
        }

        // ---- Proxy the request to the AI provider ----
        proxyStream(config, req, res);
    });
});

/* ------------------------------------------------------------------
 *  URL validation – prevent SSRF attacks
 *
 *  Custom connectors could theoretically point to internal services.
 *  We enforce: HTTPS only, no private/reserved IP ranges.
 * ------------------------------------------------------------------ */
function isAllowedUpstreamUrl(urlStr) {
    let parsed;
    try {
        parsed = new URL(urlStr);
    } catch (e) {
        return false;
    }

    if (parsed.protocol !== 'https:') return false;

    const host = parsed.hostname.toLowerCase();

    // Block obvious internal targets
    if (['localhost', '127.0.0.1', '0.0.0.0', '[::1]'].includes(host)) return false;

    // Block private IPv4 ranges
    if (net.isIPv4(host)) {
        const parts = host.split('.').map(Number);
        if (parts[0] === 10) return false; // 10.0.0.0/8
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false; // 172.16.0.0/12
        if (parts[0] === 192 && parts[1] === 168) return false; // 192.168.0.0/16
        if (parts[0] === 169 && parts[1] === 254) return false; // link-local
    }

    return true;
}

/* ------------------------------------------------------------------
 *  Proxy logic
 *
 *  Pipes raw bytes from the AI provider to the client browser.
 *  Zero parsing — this is intentionally a transparent byte pipe.
 *
 *  Works for BOTH streaming (SSE) and non-streaming (JSON) requests:
 *  - Streaming:     upstream sends text/event-stream → piped as SSE
 *  - Non-streaming: upstream sends application/json  → piped as JSON
 *
 *  All SSE parsing happens in the browser JS (chat.php handleEvent).
 *
 *  Handles:
 *  - Upstream errors and timeouts
 *  - Client disconnect (aborts upstream request to free resources)
 *  - Active stream counting for monitoring
 * ------------------------------------------------------------------ */
function proxyStream(config, clientReq, clientRes) {
    const url = new URL(config.url);
    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;

    const payload = JSON.stringify(config.payload);
    const timeoutMs = config.timeoutMs || 120000;

    // Important: do NOT set Content-Length manually (let Node handle it),
    // and avoid keep-alive to reduce flaky upstream resets.
    const outHeaders = {
        ...config.headers,
        'Connection': 'close',
    };

    // Use a non-keepalive agent for HTTPS upstream
    const agent = isHttps ? new https.Agent({ keepAlive: false }) : undefined;

    const options = {
        hostname: url.hostname,
        servername: url.hostname, // TLS SNI
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        method: config.method || 'POST',
        headers: outHeaders,
        timeout: timeoutMs,
        agent,
    };

    // Track active streams safely (avoid double decrement)
    activeStreams++;
    log('info', 'Stream start', { host: url.hostname, active: activeStreams });

    let finished = false;
    function finish(reason, meta = {}) {
        if (finished) return;
        finished = true;
        activeStreams = Math.max(0, activeStreams - 1);
        log('info', reason, { host: url.hostname, active: activeStreams, ...meta });
    }

    const proxyReq = lib.request(options, (proxyRes) => {
        const upstreamCT = proxyRes.headers['content-type'] || 'application/octet-stream';

        // Forward upstream status code + content-type; disable buffering for SSE
        clientRes.writeHead(proxyRes.statusCode || 200, {
            'Content-Type': upstreamCT,
            'Cache-Control': 'no-cache, no-transform',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
        });

        proxyRes.on('data', (chunk) => {
            // If client went away, stop work
            if (!clientRes.writableEnded) clientRes.write(chunk);
        });

        proxyRes.on('end', () => {
            finish('Stream end');
            clientRes.end();
        });

        proxyRes.on('error', (err) => {
            finish('Upstream read error', { message: err.message });
            clientRes.end();
        });
    });

    // Abort upstream ONLY when the RESPONSE connection closes (real disconnect),
    // not when the request body upload finishes.
    clientRes.on('close', () => {
        if (finished) return;
        if (!proxyReq.destroyed) proxyReq.destroy();
        finish('Client disconnected, upstream aborted');
    });

    proxyReq.on('error', (err) => {
        finish('Connect error', {
            message: err.message,
            code: err.code,
            errno: err.errno,
            syscall: err.syscall,
            address: err.address,
            port: err.port,
        });

        if (!clientRes.headersSent) {
            clientRes.writeHead(502, { 'Content-Type': 'application/json' });
        }
        clientRes.end(JSON.stringify({ error: 'Failed to connect to AI provider' }));
    });

    proxyReq.on('timeout', () => {
        // Timeout: destroy upstream, return 504
        if (!proxyReq.destroyed) proxyReq.destroy();
        finish('Upstream timeout', { timeoutMs });

        if (!clientRes.headersSent) {
            clientRes.writeHead(504, { 'Content-Type': 'application/json' });
        }
        clientRes.end(JSON.stringify({ error: 'AI provider request timed out' }));
    });

    // Send payload upstream
    proxyReq.write(payload);
    proxyReq.end();
}

/* ------------------------------------------------------------------
 *  Cleanup: periodically remove stale config files (orphaned tokens)
 *
 *  Catches edge cases where prepareChat.php wrote a config but the
 *  frontend never called /stream (e.g. user closed the tab).
 * ------------------------------------------------------------------ */
const cleanupInterval = setInterval(() => {
    try {
        if (!fs.existsSync(CONFIG_DIR)) return;
        const nowS = Date.now() / 1000;
        const maxAge = MAX_TOKEN_AGE_S * 5; // generous: 5× the normal expiry

        for (const f of fs.readdirSync(CONFIG_DIR)) {
            if (!f.endsWith('.json')) continue; // only touch expected files

            const fp = path.join(CONFIG_DIR, f);
            try {
                const stat = fs.statSync(fp);
                if (nowS - stat.mtimeMs / 1000 > maxAge) {
                    fs.unlinkSync(fp);
                    log('info', 'Cleanup: removed stale config', { file: f });
                }
            } catch (e) { /* file may have been consumed between readdir and stat */ }
        }
    } catch (e) { /* config dir may not exist yet */ }
}, 60_000);

/* ------------------------------------------------------------------
 *  Graceful shutdown
 *
 *  On SIGTERM/SIGINT (e.g. supervisord restart): stop accepting new
 *  connections, wait for active streams to finish (up to 30s), exit.
 * ------------------------------------------------------------------ */
function shutdown(signal) {
    log('info', `Received ${signal}, shutting down gracefully`, { activeStreams });

    clearInterval(cleanupInterval);
    server.close(() => {
        log('info', 'Server closed, all connections drained');
        process.exit(0);
    });

    // Force exit after 30s if streams haven't finished
    setTimeout(() => {
        log('warn', 'Force exit after timeout', { activeStreams });
        process.exit(1);
    }, 30_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

/* ------------------------------------------------------------------
 *  Start
 * ------------------------------------------------------------------ */
server.listen(PORT, HOST, () => {
    log('info', 'Stream proxy started', {
        host: HOST,
        port: PORT,
        configDir: CONFIG_DIR,
        tokenMaxAgeS: MAX_TOKEN_AGE_S,
    });
});
