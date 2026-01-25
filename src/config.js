
import { MD5MD5, maskSensitiveInfo, formatIdentifier } from './utils/helpers.js';
import { generateRandomIP, organizeToArray, getCloudflareUsage } from './utils/ip.js';

export async function readConfig(env, hostname, userID, path, reset = false) {
    const host = hostname;
    const CM_DoH = "https://doh.cmliussss.net/CMLiussss";
    const initStartTime = performance.now();

    // Default config
    const defaultConfig = {
        TIME: new Date().toISOString(),
        HOST: host,
        HOSTS: [hostname],
        UUID: userID,
        协议类型: "vless",
        传输协议: "ws",
        跳过证书验证: true,
        启用0RTT: false,
        TLS分片: null,
        随机路径: false,
        ECH: false,
        ECHConfig: {
            DNS: CM_DoH,
            SNI: null,
        },
        Fingerprint: "chrome",
        优选订阅生成: {
            local: true,
            本地IP库: {
                随机IP: true,
                随机数量: 16,
                指定端口: -1,
            },
            SUB: null,
            SUBNAME: "edgetunnel",
            SUBUpdateTime: 3,
            TOKEN: await MD5MD5(hostname + userID),
        },
        订阅转换配置: {
            SUBAPI: "https://SUBAPI.cmliussss.net",
            SUBCONFIG: "https://raw.githubusercontent.com/cmliu/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini",
            SUBEMOJI: false,
        },
        反代: {
            PROXYIP: "auto",
            SOCKS5: {
                启用: null, // Will be set later based on parsing
                全局: false,
                账号: '',
                白名单: ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'],
            },
        },
        TG: {
            启用: false,
            BotToken: null,
            ChatID: null,
        },
        CF: {
            Email: null,
            GlobalAPIKey: null,
            AccountID: null,
            APIToken: null,
            UsageAPI: null,
            Usage: {
                success: false,
                pages: 0,
                workers: 0,
                total: 0,
                max: 100000,
            },
        }
    };

    let config_JSON;
    try {
        let configStr = await env.KV.get('config.json');
        if (!configStr || reset) {
            await env.KV.put('config.json', JSON.stringify(defaultConfig, null, 2));
            config_JSON = defaultConfig;
        } else {
            config_JSON = JSON.parse(configStr);
        }
    } catch (error) {
        console.error(`读取config_JSON出错: ${error.message}`);
        config_JSON = defaultConfig;
    }

    // Dynamic updates
    config_JSON.HOST = host;
    if (!config_JSON.HOSTS) config_JSON.HOSTS = [hostname];
    if (env.HOST) config_JSON.HOSTS = (await organizeToArray(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]);
    config_JSON.UUID = userID;
    if (!config_JSON.随机路径) config_JSON.随机路径 = false;
    if (!config_JSON.启用0RTT) config_JSON.启用0RTT = false;

    // We will handle PATH and SOCKS5 parsing in the caller or passed in, 
    // but here we try to replicate logic.
    // However, the original code passes 'path' (from url) into this function.
    // Logic for setting config_JSON.PATH:
    if (!config_JSON.反代.SOCKS5) config_JSON.反代.SOCKS5 = defaultConfig.反代.SOCKS5;

    // Note: The caller should have updated config_JSON.反代.SOCKS5 with runtime values if any (from URL params)
    // But since we are reading from KV/Default, the runtime params from URL need to be merged *before* we assume they are there?
    // In original code, `config_JSON = await 读取config_JSON(env, host, userID, env.PATH);` is called.
    // Then `反代参数获取` (Get Proxy Params) is called *before* logic that might use config but `读取config_JSON` itself relies on some defaults.

    // Simplification: logic for PATH calculation
    config_JSON.PATH = path ? (path.startsWith('/') ? path : '/' + path) : (config_JSON.反代.SOCKS5.启用 ? ('/' + config_JSON.反代.SOCKS5.启用 + (config_JSON.反代.SOCKS5.全局 ? '://' : '=') + config_JSON.反代.SOCKS5.账号) : (config_JSON.反代.PROXYIP === 'auto' ? '/' : `/proxyip=${config_JSON.反代.PROXYIP}`));

    if (!config_JSON.TLS分片 && config_JSON.TLS分片 !== null) config_JSON.TLS分片 = null;
    const TLSFragParam = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
    if (!config_JSON.Fingerprint) config_JSON.Fingerprint = "chrome";
    if (!config_JSON.ECH) config_JSON.ECH = false;
    if (!config_JSON.ECHConfig) config_JSON.ECHConfig = { DNS: CM_DoH, SNI: null };
    const ECHParam = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';

    config_JSON.LINK = `${config_JSON.协议类型}://${userID}@${host}:443?security=tls&type=${config_JSON.传输协议 + ECHParam}&host=${host}&fp=${config_JSON.Fingerprint}&sni=${host}&path=${encodeURIComponent(config_JSON.启用0RTT ? config_JSON.PATH + '?ed=2560' : config_JSON.PATH) + TLSFragParam}&encryption=none${config_JSON.跳过证书验证 ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
    config_JSON.优选订阅生成.TOKEN = await MD5MD5(hostname + userID);

    // Load TG config
    const defaultTG = { BotToken: null, ChatID: null };
    config_JSON.TG = { 启用: config_JSON.TG.启用 ? config_JSON.TG.启用 : false, ...defaultTG };
    try {
        const tgStr = await env.KV.get('tg.json');
        if (!tgStr) {
            await env.KV.put('tg.json', JSON.stringify(defaultTG, null, 2));
        } else {
            const tg = JSON.parse(tgStr);
            config_JSON.TG.ChatID = tg.ChatID || null;
            config_JSON.TG.BotToken = tg.BotToken ? maskSensitiveInfo(tg.BotToken) : null;
        }
    } catch (e) {
        console.error(`读取tg.json出错: ${e.message}`);
    }

    // Load CF config
    const defaultCF = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
    config_JSON.CF = { ...defaultCF, Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 } };
    try {
        const cfStr = await env.KV.get('cf.json');
        if (!cfStr) {
            await env.KV.put('cf.json', JSON.stringify(defaultCF, null, 2));
        } else {
            const cf = JSON.parse(cfStr);
            if (cf.UsageAPI) {
                try {
                    const response = await fetch(cf.UsageAPI);
                    config_JSON.CF.Usage = await response.json();
                } catch (err) {
                    console.error(`请求 CF_JSON.UsageAPI 失败: ${err.message}`);
                }
            } else {
                config_JSON.CF.Email = cf.Email || null;
                config_JSON.CF.GlobalAPIKey = cf.GlobalAPIKey ? maskSensitiveInfo(cf.GlobalAPIKey) : null;
                config_JSON.CF.AccountID = cf.AccountID ? maskSensitiveInfo(cf.AccountID) : null;
                config_JSON.CF.APIToken = cf.APIToken ? maskSensitiveInfo(cf.APIToken) : null;
                config_JSON.CF.UsageAPI = null;
                config_JSON.CF.Usage = await getCloudflareUsage(cf.Email, cf.GlobalAPIKey, cf.AccountID, cf.APIToken);
            }
        }
    } catch (e) {
        console.error(`读取cf.json出错: ${e.message}`);
    }

    config_JSON.加载时间 = (performance.now() - initStartTime).toFixed(2) + 'ms';
    return config_JSON;
}

export async function logRequest(env, request, accessIP, type = "Get_SUB", config) {
    const limit = 4; // MB
    try {
        const now = new Date();
        const logContent = {
            TYPE: type,
            IP: accessIP,
            ASN: `AS${request.cf.asn || '0'} ${request.cf.asOrganization || 'Unknown'}`,
            CC: `${request.cf.country || 'N/A'} ${request.cf.city || 'N/A'}`,
            URL: request.url,
            UA: request.headers.get('User-Agent') || 'Unknown',
            TIME: now.getTime()
        };
        let logArray = [];
        const existingLogs = await env.KV.get('log.json');
        if (existingLogs) {
            try {
                logArray = JSON.parse(existingLogs);
                if (!Array.isArray(logArray)) { logArray = [logContent]; }
                else if (type !== "Get_SUB") {
                    const thirtyMinsAgo = now.getTime() - 30 * 60 * 1000;
                    if (logArray.some(log => log.TYPE !== "Get_SUB" && log.IP === accessIP && log.URL === request.url && log.UA === (request.headers.get('User-Agent') || 'Unknown') && log.TIME >= thirtyMinsAgo)) return;
                    logArray.push(logContent);
                    while (JSON.stringify(logArray, null, 2).length > limit * 1024 * 1024 && logArray.length > 0) logArray.shift();
                } else {
                    logArray.push(logContent);
                    while (JSON.stringify(logArray, null, 2).length > limit * 1024 * 1024 && logArray.length > 0) logArray.shift();
                }

                if (config.TG.启用) {
                    try {
                        const tgStr = await env.KV.get('tg.json');
                        const tg = JSON.parse(tgStr);
                        await sendTGMessage(tg.BotToken, tg.ChatID, logContent, config);
                    } catch (error) { console.error(`读取tg.json出错: ${error.message}`) }
                }
            } catch (e) { logArray = [logContent]; }
        } else { logArray = [logContent]; }
        await env.KV.put('log.json', JSON.stringify(logArray, null, 2));
    } catch (error) { console.error(`日志记录失败: ${error.message}`); }
}

async function sendTGMessage(botToken, chatID, log, config) {
    if (!botToken || !chatID) return;
    try {
        const timeStr = new Date(log.TIME).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
        const reqURL = new URL(log.URL);
        const msg = `<b>#${config.优选订阅生成.SUBNAME} 日志通知</b>\n\n` +
            `📌 <b>类型：</b>#${log.TYPE}\n` +
            `🌐 <b>IP：</b><code>${log.IP}</code>\n` +
            `📍 <b>位置：</b>${log.CC}\n` +
            `🏢 <b>ASN：</b>${log.ASN}\n` +
            `🔗 <b>域名：</b><code>${reqURL.host}</code>\n` +
            `🔍 <b>路径：</b><code>${reqURL.pathname + reqURL.search}</code>\n` +
            `🤖 <b>UA：</b><code>${log.UA}</code>\n` +
            `📅 <b>时间：</b>${timeStr}\n` +
            `${config.CF.Usage.success ? `📊 <b>请求用量：</b>${config.CF.Usage.total}/${config.CF.Usage.max} <b>${((config.CF.Usage.total / config.CF.Usage.max) * 100).toFixed(2)}%</b>\n` : ''}`;

        const url = `https://api.telegram.org/bot${botToken}/sendMessage?chat_id=${chatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
        return fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'Accept-Encoding': 'gzip, deflate, br',
                'User-Agent': log.UA || 'Unknown',
            }
        });
    } catch (error) { console.error('Error sending message:', error) }
}
