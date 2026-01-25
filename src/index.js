
import { readConfig } from './config.js';
import { handleLogin, checkAuth, handleLogout } from './controllers/auth.js';
import { handleAdmin } from './controllers/admin.js';
import { handleSub } from './controllers/sub.js';
import { handleWSRequest } from './core/proxy.js';
import { MD5MD5, uuidRegex } from './utils/helpers.js';
import { nginx, html1101, fetchMasquerade } from './utils/pages.js';

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

        // --- WS Handling ---
        if (upgradeHeader === 'websocket') {
            if (adminPassword) {
                let proxyConfig = {
                    proxyIP: env.PROXYIP || 'auto',
                    socks5Type: null,
                    socks5Account: '',
                    socks5Global: false,
                    socks5Whitelist: ['*tapecontent.net', 'scholar.google.com'],
                    cachedProxyIndexRef: { value: 0 },
                    enableProxyFallback: true
                };

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

        const staticPage = 'https://edt-pages.github.io';
        if (!adminPassword) return fetch(staticPage + '/noADMIN');

        if (env.KV && typeof env.KV.get === 'function') {
            if (path === secretKey && secretKey !== '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改') {
                const params = new URLSearchParams(url.search);
                params.set('token', await MD5MD5(url.hostname + userID));
                return new Response('Redir...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
            }
            if (pathLower === 'login') {
                const auth = await checkAuth(request, env, { UUID: userID });
                if (auth) return new Response('Redir...', { status: 302, headers: { 'Location': '/admin' } });
                return handleLogin(request, env);
            }
            if (pathLower === 'logout' || uuidRegex.test(path)) {
                return handleLogout();
            }
            if (pathLower === 'admin' || pathLower.startsWith('admin/')) {
                const auth = await checkAuth(request, env, { UUID: userID });
                if (!auth) return new Response('Redir...', { status: 302, headers: { 'Location': '/login' } });
                const config = await readConfig(env, url.hostname, userID, path);
                return handleAdmin(request, env, config, pathLower);
            }
            if (pathLower === 'sub') {
                const config = await readConfig(env, url.hostname, userID, path);
                return handleSub(request, env, config);
            }
            if (pathLower === 'locations') {
                return fetch('https://speed.cloudflare.com/locations');
            }
            if (pathLower === 'robots.txt') return new Response('User-agent: *\nDisallow: /');
        } else if (!envUUID) {
            return fetch(staticPage + '/noKV');
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
