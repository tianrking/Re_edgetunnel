
import { readConfig, logRequest } from "../config.js";
import { getCloudflareUsage, requestOptimalAPI, generateRandomIP } from "../utils/ip.js";
import { getSocks5Account } from "../utils/helpers.js";
import { socks5Connect, httpConnect } from "../protocols/socks5.js";

async function checkSocksProxy(protocol, param) {
    const startTime = Date.now();
    let parsed;
    try { parsed = await getSocks5Account(param); } catch (err) { return { success: false, error: err.message, proxy: protocol + "://" + param, responseTime: Date.now() - startTime }; }

    try {
        const initialData = new Uint8Array(0);
        const tcpSocket = protocol == 'socks5' ? await socks5Connect('check.socks5.090227.xyz', 80, initialData, parsed) : await httpConnect('check.socks5.090227.xyz', 80, initialData, parsed);
        if (!tcpSocket) return { success: false, error: '无法连接到代理服务器', proxy: protocol + "://" + param, responseTime: Date.now() - startTime };
        try {
            const writer = tcpSocket.writable.getWriter(), encoder = new TextEncoder();
            await writer.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: check.socks5.090227.xyz\r\nConnection: close\r\n\r\n`));
            writer.releaseLock();
            const reader = tcpSocket.readable.getReader(), decoder = new TextDecoder();
            let response = '';
            try { while (true) { const { done, value } = await reader.read(); if (done) break; response += decoder.decode(value, { stream: true }); } } finally { reader.releaseLock(); }
            await tcpSocket.close();
            return { success: true, proxy: protocol + "://" + param, ip: response.match(/ip=(.*)/)?.[1], loc: response.match(/loc=(.*)/)?.[1], responseTime: Date.now() - startTime };
        } catch (error) {
            try { await tcpSocket.close(); } catch (e) { }
            return { success: false, error: error.message, proxy: protocol + "://" + param, responseTime: Date.now() - startTime };
        }
    } catch (error) { return { success: false, error: error.message, proxy: protocol + "://" + param, responseTime: Date.now() - startTime }; }
}

export async function handleAdmin(request, env, config, path) {
    const url = new URL(request.url);
    const accessIP = request.headers.get('CF-Connecting-IP') || 'Unknown';

    if (path === 'admin/log.json') {
        const logs = await env.KV.get('log.json') || '[]';
        return new Response(logs, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
    } else if (path === 'admin/getCloudflareUsage') {
        const email = url.searchParams.get('Email');
        const key = url.searchParams.get('GlobalAPIKey');
        const accountId = url.searchParams.get('AccountID');
        const token = url.searchParams.get('APIToken');
        try {
            const usage = await getCloudflareUsage(email, key, accountId, token);
            return new Response(JSON.stringify(usage, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
        } catch (err) {
            return new Response(JSON.stringify({ msg: 'Failed', error: err.message }, null, 2), { status: 500 });
        }
    } else if (path === 'admin/getADDAPI') {
        if (url.searchParams.get('url')) {
            try {
                const testUrl = url.searchParams.get('url');
                const [ips, links, needed] = await requestOptimalAPI([testUrl], url.searchParams.get('port') || '443');
                // data is first item of ips which is array?
                const resultIP = ips[0] || (links.length > 0 ? links[0] : null) || 'N/A';
                return new Response(JSON.stringify({ success: true, data: resultIP }, null, 2), { status: 200 });
            } catch (err) {
                return new Response(JSON.stringify({ msg: 'Failed', error: err.message }, null, 2), { status: 500 });
            }
        }
        return new Response(JSON.stringify({ success: false, data: [] }), { status: 403 });
    } else if (path === 'admin/check') {
        if (url.searchParams.has('socks5')) {
            const res = await checkSocksProxy('socks5', url.searchParams.get('socks5'));
            return new Response(JSON.stringify(res, null, 2), { status: 200 });
        } else if (url.searchParams.has('http')) {
            const res = await checkSocksProxy('http', url.searchParams.get('http'));
            return new Response(JSON.stringify(res, null, 2), { status: 200 });
        }
        return new Response(JSON.stringify({ error: 'Missing defined parameters' }), { status: 400 });
    } else if (path === 'admin/init') {
        try {
            const newConfig = await readConfig(env, config.HOST, config.UUID, config.PATH, true); // true to reset
            config = newConfig;
            config.init = 'Config reset to default';
            return new Response(JSON.stringify(config, null, 2), { status: 200 });
        } catch (err) {
            return new Response(JSON.stringify({ error: err.message }), { status: 500 });
        }
    } else if (request.method === 'POST') {
        if (path === 'admin/config.json') {
            try {
                const newConfig = await request.json();
                if (!newConfig.UUID || !newConfig.HOST) return new Response(JSON.stringify({ error: 'Incomplete config' }), { status: 400 });
                await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
                return new Response(JSON.stringify({ success: true }), { status: 200 });
            } catch (err) {
                return new Response(JSON.stringify({ error: err.message }), { status: 500 });
            }
        } else if (path === 'admin/cf.json') {
            try {
                const newConfig = await request.json();
                const CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
                if (newConfig.Email && newConfig.GlobalAPIKey) {
                    CF_JSON.Email = newConfig.Email;
                    CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey;
                } else if (newConfig.AccountID && newConfig.APIToken) {
                    CF_JSON.AccountID = newConfig.AccountID;
                    CF_JSON.APIToken = newConfig.APIToken;
                } else if (newConfig.UsageAPI) {
                    CF_JSON.UsageAPI = newConfig.UsageAPI;
                }
                await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
                return new Response(JSON.stringify({ success: true }), { status: 200 });
            } catch (err) {
                return new Response(JSON.stringify({ error: err.message }), { status: 500 });
            }
        } else if (path === 'admin/tg.json') {
            try {
                const newConfig = await request.json();
                const TG_JSON = { BotToken: null, ChatID: null };
                if (newConfig.BotToken && newConfig.ChatID) {
                    TG_JSON.BotToken = newConfig.BotToken;
                    TG_JSON.ChatID = newConfig.ChatID;
                }
                await env.KV.put('tg.json', JSON.stringify(TG_JSON, null, 2));
                return new Response(JSON.stringify({ success: true }), { status: 200 });
            } catch (err) {
                return new Response(JSON.stringify({ error: err.message }), { status: 500 });
            }
        } else if (path === 'admin/ADD.txt') {
            try {
                const txt = await request.text();
                await env.KV.put('ADD.txt', txt);
                return new Response(JSON.stringify({ success: true }), { status: 200 });
            } catch (err) {
                return new Response(JSON.stringify({ error: err.message }), { status: 500 });
            }
        }
    } else if (path === 'admin/config.json') {
        return new Response(JSON.stringify(config, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } else if (path === 'admin/ADD.txt') {
        let localIPs = await env.KV.get('ADD.txt') || 'null';
        if (localIPs == 'null') {
            const [ips, str] = await generateRandomIP(request, config.优选订阅生成.本地IP库.随机数量, config.优选订阅生成.本地IP库.指定端口);
            localIPs = str;
        }
        return new Response(localIPs, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
    } else if (path === 'admin/cf.json') {
        return new Response(JSON.stringify(request.cf, null, 2), { status: 200 });
    }

    return fetch('https://edt-pages.github.io/admin');
}
