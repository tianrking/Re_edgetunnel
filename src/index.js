
import { readConfig } from './config.js';
import { handleLogin, checkAuth, handleLogout } from './controllers/auth.js';
import { handleAdmin } from './controllers/admin.js';
import { handleSub } from './controllers/sub.js';
import { handleWSRequest } from './core/proxy.js';
import { MD5MD5, uuidRegex } from './utils/helpers.js';
import { nginx, html1101, fetchMasquerade } from './utils/pages.js';
import { parseConcurrentDialCount } from './core/dialer.js';
import { parseSpeedTestDomains, parseSpeedTestMode } from './core/speedtest.js';
import { handleGrpcRequest, handleXHttpRequest } from './core/http-tunnel.js';
import { parseUpstreamProxy } from './protocols/upstream.js';

async function looksLikeGrpcPayload(request) {
    try {
        const clone = request.clone();
        const reader = clone.body?.getReader();
        if (!reader) return true;
        let prefix = new Uint8Array(0);
        while (prefix.byteLength < 6) {
            const { done, value } = await reader.read();
            if (done) break;
            if (!value?.byteLength) continue;
            const joined = new Uint8Array(prefix.byteLength + value.byteLength);
            joined.set(prefix);
            joined.set(value, prefix.byteLength);
            prefix = joined;
        }
        try { await reader.cancel(); } catch { }
        if (prefix.byteLength < 6 || prefix[0] !== 0) return false;
        const frameLength = new DataView(prefix.buffer, prefix.byteOffset, prefix.byteLength).getUint32(1);
        return frameLength > 0 && frameLength <= 1024 * 1024 && prefix[5] === 0x0a;
    } catch {
        // If the platform cannot tee the request body, preserve the legacy
        // application/grpc routing rather than rejecting a valid request.
        return true;
    }
}

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const upgradeHeader = request.headers.get('Upgrade');
        const adminPassword = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
        const secretKey = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';

        let userIDMD5 = '';
        try {
            userIDMD5 = await MD5MD5(adminPassword + secretKey);
        } catch (e) { userIDMD5 = '00000000-0000-0000-0000-000000000000'; }

        const envUUID = env.UUID || env.uuid;
        const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');

        const accessIP = request.headers.get('X-Real-IP') || request.headers.get('CF-Connecting-IP') || 'Unknown';
        const path = url.pathname.slice(1);
        const pathLower = path.toLowerCase();

        const createProxyConfig = () => ({
            proxyIP: env.PROXYIP || null,
            socks5Type: null,
            socks5Account: '',
            socks5Global: false,
            socks5Whitelist: [],
            cachedProxyIndexRef: { value: 0 },
            enableProxyFallback: Boolean(env.PROXYIP),
            tcpConcurrentDial: parseConcurrentDialCount(env.TCP_CONCURRENT_DIAL),
            proxyConcurrentDial: parseConcurrentDialCount(env.PROXY_CONCURRENT_DIAL),
            speedTestMode: parseSpeedTestMode(env.SPEEDTEST_MODE),
            speedTestDomains: parseSpeedTestDomains(env.SPEEDTEST_DOMAINS),
            upstreamProxy: parseUpstreamProxy(env.UPSTREAM_PROXY),
            dnsResolver: env.DNS_RESOLVER ? {
                hostname: env.DNS_RESOLVER,
                port: Number(env.DNS_RESOLVER_PORT || 53),
            } : null,
        });

        // --- WS Handling ---
        if (upgradeHeader === 'websocket') {
            if (adminPassword) {
                let proxyConfig = createProxyConfig();

                const proxyMatch = pathLower.match(/\/(proxyip[.=]|pyip=|ip=)(.+)/);
                if (url.searchParams.has('proxyip')) {
                    const p = url.searchParams.get('proxyip');
                    proxyConfig.proxyIP = p.includes(',') ? p.split(',')[Math.floor(Math.random() * p.split(',').length)] : p;
                    proxyConfig.enableProxyFallback = false;
                } else if (proxyMatch) {
                    const p = proxyMatch[1] === 'proxyip.' ? `proxyip.${proxyMatch[2]}` : proxyMatch[2];
                    proxyConfig.proxyIP = p.includes(',') ? p.split(',')[Math.floor(Math.random() * p.split(',').length)] : p;
                    proxyConfig.enableProxyFallback = false;
                }

                return await handleWSRequest(request, userID, proxyConfig);
            }
        }

        // --- HTTP Handling ---
        if (url.protocol === 'http:') return Response.redirect(url.href.replace('http:', 'https:'), 301);

        if (!adminPassword) return new Response('Administrator password is not configured.', { status: 503 });

        const contentType = request.headers.get('content-type')?.toLowerCase() || '';
        const isReservedHttpRoute = pathLower === 'login' || pathLower === 'sub' || pathLower.startsWith('admin/');
        if (request.method === 'POST' && !isReservedHttpRoute) {
            const referer = request.headers.get('referer') || '';
            if (contentType.startsWith('application/octet-stream')) {
                return handleXHttpRequest(request, userID, createProxyConfig());
            }
            if (contentType.startsWith('application/grpc')) {
                // XHTTP stream-one can camouflage itself as application/grpc,
                // but its body starts with the raw VLESS header. Real gRPC
                // starts with a five-byte frame header followed by the hunk
                // field (0x0a).
                if (referer.includes('x_padding=') || !(await looksLikeGrpcPayload(request))) {
                    return handleXHttpRequest(request, userID, createProxyConfig());
                }
                return handleGrpcRequest(request, userID, createProxyConfig());
            }
        }

        if (env.KV && typeof env.KV.get === 'function') {
            if (path === secretKey && secretKey !== '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改') {
                const params = new URLSearchParams(url.search);
                params.set('token', await MD5MD5(url.hostname + userID));
                return new Response('Redir...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
            }
            if (pathLower === 'login') {
                const auth = await checkAuth(request, env);
                if (auth) return new Response('Redir...', { status: 302, headers: { 'Location': '/admin' } });
                return handleLogin(request, env);
            }
            if (pathLower === 'logout' || uuidRegex.test(path)) {
                return handleLogout(request, env);
            }
            if (pathLower === 'admin' || pathLower.startsWith('admin/')) {
                const auth = await checkAuth(request, env);
                if (!auth) return new Response('Redir...', { status: 302, headers: { 'Location': '/login' } });
                const config = await readConfig(env, url.hostname, userID, path);
                return handleAdmin(request, env, config, pathLower);
            }
            if (pathLower === 'sub') {
                const expectedToken = await MD5MD5(url.hostname + userID);
                if (url.searchParams.get('token') !== expectedToken) {
                    return new Response(JSON.stringify({ success: false, msg: 'Invalid Token' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                }
                const config = await readConfig(env, url.hostname, userID, path);
                return handleSub(request, env, config, ctx);
            }
            if (pathLower === 'locations') {
                if (!env.LOCATIONS_API) {
                    return new Response('Location data is disabled. Configure an operator-owned LOCATIONS_API to enable it.', { status: 501 });
                }
                try {
                    const locationsUrl = new URL(env.LOCATIONS_API);
                    if (locationsUrl.protocol !== 'https:' || locationsUrl.username || locationsUrl.password) throw new Error('invalid endpoint');
                    return fetch(locationsUrl, { headers: { Accept: 'application/json' } });
                } catch {
                    return new Response('Invalid LOCATIONS_API configuration.', { status: 500 });
                }
            }
            if (pathLower === 'robots.txt') return new Response('User-agent: *\nDisallow: /');
        } else if (!envUUID) {
            return new Response('KV binding or UUID configuration is required.', { status: 503 });
        }

        let masqueradeUrl = env.URL || 'nginx';
        if (masqueradeUrl && masqueradeUrl !== 'nginx' && masqueradeUrl !== '1101') {
            masqueradeUrl = masqueradeUrl.trim().replace(/\/$/, '');
            if (!masqueradeUrl.match(/^https?:\/\//i)) masqueradeUrl = 'https://' + masqueradeUrl;
        }

        if (masqueradeUrl === '1101') return new Response(html1101(url.host, accessIP), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
        if (masqueradeUrl === 'nginx') return new Response(nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });

        try {
            return await fetchMasquerade(masqueradeUrl, request);
        } catch (e) { }

        return new Response(nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
    }
};
