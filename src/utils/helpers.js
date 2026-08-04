
export const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;

function md5Hex(text) {
    const input = new TextEncoder().encode(text);
    const length = input.length;
    const paddedLength = (length + 9 + 63) & ~63;
    const bytes = new Uint8Array(paddedLength);
    bytes.set(input);
    bytes[length] = 0x80;
    const view = new DataView(bytes.buffer);
    const bitLength = length * 8;
    view.setUint32(paddedLength - 8, bitLength >>> 0, true);
    view.setUint32(paddedLength - 4, Math.floor(bitLength / 0x1_0000_0000), true);

    const shifts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
    const constants = Array.from({ length: 64 }, (_, index) => Math.floor(Math.abs(Math.sin(index + 1)) * 0x1_0000_0000) >>> 0);
    const rotateLeft = (value, amount) => ((value << amount) | (value >>> (32 - amount))) >>> 0;
    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

    for (let offset = 0; offset < paddedLength; offset += 64) {
        const words = Array.from({ length: 16 }, (_, index) => view.getUint32(offset + index * 4, true));
        let a = a0, b = b0, c = c0, d = d0;
        for (let index = 0; index < 64; index++) {
            let f, g;
            if (index < 16) { f = (b & c) | (~b & d); g = index; }
            else if (index < 32) { f = (d & b) | (~d & c); g = (5 * index + 1) % 16; }
            else if (index < 48) { f = b ^ c ^ d; g = (3 * index + 5) % 16; }
            else { f = c ^ (b | ~d); g = (7 * index) % 16; }
            const next = d;
            d = c;
            c = b;
            b = (b + rotateLeft((a + f + constants[index] + words[g]) >>> 0, shifts[index])) >>> 0;
            a = next;
        }
        a0 = (a0 + a) >>> 0;
        b0 = (b0 + b) >>> 0;
        c0 = (c0 + c) >>> 0;
        d0 = (d0 + d) >>> 0;
    }

    const digest = new Uint8Array(16);
    const digestView = new DataView(digest.buffer);
    [a0, b0, c0, d0].forEach((value, index) => digestView.setUint32(index * 4, value, true));
    return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function MD5MD5(text) {
    return md5Hex(md5Hex(text).slice(7, 27));
}

export function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try {
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return { earlyData: bytes.buffer, error: null };
    } catch (error) {
        return { error };
    }
}

export function isSafeConnectTarget(hostname, port) {
    return typeof hostname === 'string' && hostname.length > 0 && hostname.length <= 255 &&
        !/[\r\n\0\s]/.test(hostname) && Number.isInteger(port) && port > 0 && port <= 65535;
}

export function normalizeProxyProtocol(value) {
    return String(value || '').toLowerCase() === 'trojan' ? 'trojan' : 'vless';
}

export function normalizeTransport(value) {
    const transport = String(value || '').toLowerCase();
    return ['ws', 'xhttp', 'grpc'].includes(transport) ? transport : 'ws';
}

export function buildProxyUri({ protocol, credential, address, port = 443, host, transport = 'ws', path = '/', fingerprint = 'chrome', name = 'edgetunnel', skipCertificateVerification = false, ech = null, fragment = null }) {
    const normalizedProtocol = normalizeProxyProtocol(protocol);
    const normalizedTransport = normalizeTransport(transport);
    const params = new URLSearchParams({
        security: 'tls',
        type: normalizedTransport,
        host,
        fp: fingerprint,
        sni: host,
    });
    if (normalizedTransport === 'grpc') {
        params.set('serviceName', String(path || '/').replace(/^\/+/, ''));
        params.set('mode', 'gun');
    } else {
        params.set('path', path);
        if (normalizedTransport === 'xhttp') params.set('mode', 'stream-one');
    }
    if (normalizedProtocol === 'vless') params.set('encryption', 'none');
    if (skipCertificateVerification) {
        params.set('insecure', '1');
        params.set('allowInsecure', '1');
    }
    if (ech) params.set('ech', ech);
    if (fragment) params.set('fragment', fragment);
    const formattedAddress = String(address).includes(':') && !String(address).startsWith('[')
        ? `[${address}]`
        : address;
    return `${normalizedProtocol}://${encodeURIComponent(credential)}@${formattedAddress}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

export function buildShadowsocksUri({
    method = 'aes-128-gcm',
    password,
    address,
    port = 443,
    host,
    path = '/',
    name = 'edgetunnel',
    tls = true,
}) {
    const normalizedMethod = ['aes-128-gcm', 'aes-256-gcm'].includes(String(method).toLowerCase())
        ? String(method).toLowerCase()
        : 'aes-128-gcm';
    const credentials = btoa(`${normalizedMethod}:${password}`)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    const pluginPath = `${path}${String(path).includes('?') ? '&' : '?'}enc=${encodeURIComponent(normalizedMethod)}`;
    // The Worker implements the standard Shadowsocks AEAD stream. Mihomo's
    // v2ray-plugin defaults to its mux extension, which is a different wire
    // protocol, so explicitly disable mux in generated links.
    const plugin = `v2ray-plugin;mode=websocket;host=${host};path=${pluginPath}${tls ? ';tls' : ''};mux=0`;
    const params = new URLSearchParams({ plugin });
    const formattedAddress = String(address).includes(':') && !String(address).startsWith('[')
        ? `[${address}]`
        : address;
    return `ss://${credentials}@${formattedAddress}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

export function isValidBase64(str) {
    if (typeof str !== 'string') return false;
    const cleanStr = str.replace(/\s/g, '');
    if (cleanStr.length === 0 || cleanStr.length % 4 !== 0) return false;
    const base64Regex = /^[A-Za-z0-9+/]+={0,2}$/;
    if (!base64Regex.test(cleanStr)) return false;
    try {
        atob(cleanStr);
        return true;
    } catch {
        return false;
    }
}

export function base64Decode(str) {
    const bytes = new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
    const decoder = new TextDecoder('utf-8');
    return decoder.decode(bytes);
}

export function formatIdentifier(arr, offset = 0) {
    const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

export function maskSensitiveInfo(text, prefixLen = 3, suffixLen = 2) {
    if (!text || typeof text !== 'string') return text;
    if (text.length <= prefixLen + suffixLen) return text;

    const prefix = text.slice(0, prefixLen);
    const suffix = text.slice(-suffixLen);
    const starCount = text.length - prefixLen - suffixLen;

    return `${prefix}${'*'.repeat(starCount)}${suffix}`;
}

export function randomPath() {
    const commonPaths = ["about", "account", "acg", "act", "activity", "ad", "ads", "ajax", "album", "albums", "anime", "api", "app", "apps", "archive", "archives", "article", "articles", "ask", "auth", "avatar", "bbs", "bd", "blog", "blogs", "book", "books", "bt", "buy", "cart", "category", "categories", "cb", "channel", "channels", "chat", "china", "city", "class", "classify", "clip", "clips", "club", "cn", "code", "collect", "collection", "comic", "comics", "community", "company", "config", "contact", "content", "course", "courses", "cp", "data", "detail", "details", "dh", "directory", "discount", "discuss", "dl", "dload", "doc", "docs", "document", "documents", "doujin", "download", "downloads", "drama", "edu", "en", "ep", "episode", "episodes", "event", "events", "f", "faq", "favorite", "favourites", "favs", "feedback", "file", "files", "film", "films", "forum", "forums", "friend", "friends", "game", "games", "gif", "go", "go.html", "go.php", "group", "groups", "help", "home", "hot", "htm", "html", "image", "images", "img", "index", "info", "intro", "item", "items", "ja", "jp", "jump", "jump.html", "jump.php", "jumping", "knowledge", "lang", "lesson", "lessons", "lib", "library", "link", "links", "list", "live", "lives", "m", "mag", "magnet", "mall", "manhua", "map", "member", "members", "message", "messages", "mobile", "movie", "movies", "music", "my", "new", "news", "note", "novel", "novels", "online", "order", "out", "out.html", "out.php", "outbound", "p", "page", "pages", "pay", "payment", "pdf", "photo", "photos", "pic", "pics", "picture", "pictures", "play", "player", "playlist", "post", "posts", "product", "products", "program", "programs", "project", "qa", "question", "rank", "ranking", "read", "readme", "redirect", "redirect.html", "redirect.php", "reg", "register", "res", "resource", "retrieve", "sale", "search", "season", "seasons", "section", "seller", "series", "service", "services", "setting", "settings", "share", "shop", "show", "shows", "site", "soft", "sort", "source", "special", "star", "stars", "static", "stock", "store", "stream", "streaming", "streams", "student", "study", "tag", "tags", "task", "teacher", "team", "tech", "temp", "test", "thread", "tool", "tools", "topic", "topics", "torrent", "trade", "travel", "tv", "txt", "type", "u", "upload", "uploads", "url", "urls", "user", "users", "v", "version", "video", "videos", "view", "vip", "vod", "watch", "web", "wenku", "wiki", "work", "www", "zh", "zh-cn", "zh-tw", "zip"];
    const randomCount = Math.floor(Math.random() * 3 + 1);
    const path = commonPaths.sort(() => 0.5 - Math.random()).slice(0, randomCount).join('/');
    return `/${path}`;
}

export function randomReplaceWildcard(h) {
    if (!h?.includes('*')) return h;
    const charset = 'abcdefghijklmnopqrstuvwxyz0123456789';
    return h.replace(/\*/g, () => {
        let s = '';
        for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++)
            s += charset[Math.floor(Math.random() * 36)];
        return s;
    });
}

export function batchReplaceDomain(content, hosts, groupSize = 2) {
    const shuffledHosts = [...hosts].sort(() => Math.random() - 0.5);
    let count = 0, currentRandomHost = null;
    return content.replace(/example\.com/g, () => {
        if (count % groupSize === 0) currentRandomHost = randomReplaceWildcard(shuffledHosts[Math.floor(count / groupSize) % shuffledHosts.length]);
        count++;
        return currentRandomHost;
    });
}

export function sha224(s) {
    const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
    try { s = unescape(encodeURIComponent(s)); } catch (e) { console.error(e); return s; }
    const l = s.length * 8; s += String.fromCharCode(0x80);
    while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
    const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
    const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
    s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
    const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
    for (let i = 0; i < w.length; i += 16) {
        const x = new Array(64).fill(0);
        for (let j = 0; j < 16; j++)x[j] = w[i + j];
        for (let j = 16; j < 64; j++) {
            const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
            const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
            x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
        }
        let [a, b, c, d, e, f, g, h0] = h;
        for (let j = 0; j < 64; j++) {
            const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
            const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
            h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
        }
        for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
    }
    let hex = '';
    for (let i = 0; i < 7; i++) {
        for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
    }
    return hex;
}

export async function getSocks5Account(address) {
    if (address.includes('@')) {
        const lastAtIndex = address.lastIndexOf('@');
        let userPassword = address.substring(0, lastAtIndex).replaceAll('%3D', '=');
        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
        if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
        address = `${userPassword}@${address.substring(lastAtIndex + 1)}`;
    }
    const atIndex = address.lastIndexOf("@");
    const [hostPart, authPart] = atIndex === -1 ? [address, undefined] : [address.substring(atIndex + 1), address.substring(0, atIndex)];

    let username, password;
    if (authPart) {
        [username, password] = authPart.split(":");
        if (!password) throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
    }

    let hostname, port;
    if (hostPart.includes("]:")) {
        [hostname, port] = [hostPart.split("]:")[0] + "]", Number(hostPart.split("]:")[1].replace(/[^\d]/g, ''))];
    } else if (hostPart.startsWith("[")) {
        [hostname, port] = [hostPart, 80];
    } else {
        const parts = hostPart.split(":");
        [hostname, port] = parts.length === 2 ? [parts[0], Number(parts[1].replace(/[^\d]/g, ''))] : [hostPart, 80];
    }

    if (isNaN(port)) throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
    if (hostname.includes(":") && !/^\[.*\]$/.test(hostname)) throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');

    return { username, password, hostname, port };
}
