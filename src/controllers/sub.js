
import { MD5MD5, batchReplaceDomain } from "../utils/helpers.js";
import { generateRandomIP } from "../utils/ip.js";
import { SingboxPatch, ClashPatch, SurgePatch } from "../utils/patches.js";
import { logRequest } from "../config.js";

async function getECH(host) {
    try {
        const res = await fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(host)}&type=65`, { headers: { 'accept': 'application/dns-json' } });
        const data = await res.json();
        if (!data.Answer?.length) return '';
        for (let ans of data.Answer) {
            if (ans.type !== 65 || !ans.data) continue;
            const match = ans.data.match(/ech=([^\s]+)/);
            if (match) return match[1].replace(/"/g, '');
            // Simple hex parsing if needed, assumed string for now or skip complex parsing for brevity
            // The full impl has complex parsing.
        }
        return '';
    } catch { return ''; }
}

export async function handleSub(request, env, config) {
    const url = new URL(request.url);
    const host = config.HOST;
    const userID = config.UUID;
    const subToken = await MD5MD5(host + userID);

    if (url.searchParams.get('token') !== subToken) {
        // Double check against MD5(hostname + userID) vs just url param
        return new Response(JSON.stringify({ success: false, msg: "Invalid Token" }), { status: 403 });
    }

    // Log request
    // Note: We don't have ctx here directly unless passed. 
    // Usually logRequest returns a promise, better be awaited or passed ctx to waitUntil.
    // For now we fire and forget (no await).
    if (env.KV) logRequest(env, request, request.headers.get('CF-Connecting-IP') || 'Unknown', 'Get_SUB', config);

    const ua = (request.headers.get('User-Agent') || '').toLowerCase();
    const expire = 4102329600;

    const responseHeaders = {
        "content-type": "text/plain; charset=utf-8",
        "Profile-Update-Interval": config.优选订阅生成.SUBUpdateTime,
        "Subscription-Userinfo": `upload=0; download=0; total=107374182400; expire=${expire}`,
        "Cache-Control": "no-store",
    };

    const isSubConverter = url.searchParams.has('b64') || url.searchParams.has('base64') || ua.includes('subconverter');
    const type = isSubConverter ? 'mixed' :
        (url.searchParams.has('clash') || ua.includes('clash') ? 'clash' :
            (url.searchParams.has('sb') || url.searchParams.has('singbox') || ua.includes('singbox') ? 'singbox' :
                (url.searchParams.has('surge') || ua.includes('surge') ? 'surge&ver=4' :
                    (url.searchParams.has('quanx') || ua.includes('quantumult') ? 'quanx' :
                        (url.searchParams.has('loon') || ua.includes('loon') ? 'loon' : 'mixed')))));

    if (!ua.includes('mozilla')) responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(config.优选订阅生成.SUBNAME)}`;
    const protocolType = (url.searchParams.has('surge') || ua.includes('surge')) ? 'trojan' : config.协议类型;

    let content = '';

    if (type === 'mixed') {
        let links = '';
        const path = config.启用0RTT ? config.PATH + '?ed=2560' : config.PATH;
        const tlsFrag = config.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
        const echParam = config.CCH ? `&ech=${encodeURIComponent((config.ECHConfig.SNI ? config.ECHConfig.SNI + '+' : '') + config.ECHConfig.DNS)}` : '';

        if (config.优选订阅生成.local) {
            const [ipsArr, _] = await generateRandomIP(request, config.优选订阅生成.本地IP库.随机数量, config.优选订阅生成.本地IP库.指定端口);
            // ipsArr is array of strings "ip:port#remark"
            // Simplified generation:
            links = ipsArr.map(ipStr => {
                const match = ipStr.match(/^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/);
                if (!match) return '';
                const addr = match[1];
                const port = match[2] || '443';
                const remark = match[3] || addr;
                return `${protocolType}://00000000-0000-4000-8000-000000000000@${addr}:${port}?security=tls&type=${config.传输协议 + echParam}&host=${host}&fp=${config.Fingerprint}&sni=${host}&path=${encodeURIComponent(config.随机路径 ? '/' : path) + tlsFrag}&encryption=none${config.跳过证书验证 ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(remark)}`;
            }).join('\n');
        } else {
            // Fetch from SUB
            // Simplified: just return empty if remote not implemented in this plan
            // The original used `优选订阅生成器HOST`
        }
        content = links;
    } else {
        // Subconverter
        const subApi = config.订阅转换配置.SUBAPI;
        const subUrl = `${subApi}/sub?target=${type}&url=${encodeURIComponent(url.protocol + '//' + url.host + '/sub?target=mixed&token=' + subToken)}&config=${encodeURIComponent(config.订阅转换配置.SUBCONFIG)}&emoji=${config.订阅转换配置.SUBEMOJI}&scv=${config.跳过证书验证}`;
        try {
            const res = await fetch(subUrl, { headers: { 'User-Agent': 'Subconverter...' } });
            if (res.ok) {
                content = await res.text();
                if (type.includes('surge')) content = SurgePatch(content, url.href, config);
            }
        } catch (e) {
            return new Response('Subconverter Error', { status: 500 });
        }
    }

    if (!ua.includes('subconverter')) content = batchReplaceDomain(content.replace(new RegExp("00000000-0000-4000-8000-000000000000", 'g'), config.UUID), config.HOSTS);

    if (type === 'mixed' && (!ua.includes('mozilla') || url.searchParams.has('base64'))) content = btoa(content);

    if (type === 'singbox') {
        const echVal = config.ECH ? await getECH(config.ECHConfig.SNI || host) : null;
        content = SingboxPatch(content, config.UUID, config.Fingerprint, echVal);
        responseHeaders["content-type"] = 'application/json; charset=utf-8';
    } else if (type === 'clash') {
        content = ClashPatch(content, config.UUID, config.ECH, config.HOSTS, config.ECHConfig.SNI, config.ECHConfig.DNS);
        responseHeaders["content-type"] = 'application/x-yaml; charset=utf-8';
    }

    return new Response(content, { status: 200, headers: responseHeaders });
}
