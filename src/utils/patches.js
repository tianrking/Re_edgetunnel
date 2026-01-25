
export function SingboxPatch(content, uuid, fingerprint, ech_config) {
    const sb_json_text = content.replace('1.1.1.1', '8.8.8.8').replace('1.0.0.1', '8.8.4.4');
    try {
        let config = JSON.parse(sb_json_text);
        if (Array.isArray(config.inbounds)) {
            config.inbounds.forEach(inbound => {
                if (inbound.type === 'tun') {
                    const addresses = [];
                    if (inbound.inet4_address) addresses.push(inbound.inet4_address);
                    if (inbound.inet6_address) addresses.push(inbound.inet6_address);
                    if (addresses.length > 0) {
                        inbound.address = addresses;
                        delete inbound.inet4_address;
                        delete inbound.inet6_address;
                    }
                    const route_addresses = [];
                    if (Array.isArray(inbound.inet4_route_address)) route_addresses.push(...inbound.inet4_route_address);
                    if (Array.isArray(inbound.inet6_route_address)) route_addresses.push(...inbound.inet6_route_address);
                    if (route_addresses.length > 0) {
                        inbound.route_address = route_addresses;
                        delete inbound.inet4_route_address;
                        delete inbound.inet6_route_address;
                    }
                    const route_exclude_addresses = [];
                    if (Array.isArray(inbound.inet4_route_exclude_address)) route_exclude_addresses.push(...inbound.inet4_route_exclude_address);
                    if (Array.isArray(inbound.inet6_route_exclude_address)) route_exclude_addresses.push(...inbound.inet6_route_exclude_address);
                    if (route_exclude_addresses.length > 0) {
                        inbound.route_exclude_address = route_exclude_addresses;
                        delete inbound.inet4_route_exclude_address;
                        delete inbound.inet6_route_exclude_address;
                    }
                }
            });
        }

        const ruleSetsDefinitions = new Map();
        const processRules = (rules, isDns = false) => {
            if (!Array.isArray(rules)) return;
            rules.forEach(rule => {
                if (rule.geosite) {
                    const list = Array.isArray(rule.geosite) ? rule.geosite : [rule.geosite];
                    rule.rule_set = list.map(name => {
                        const tag = `geosite-${name}`;
                        if (!ruleSetsDefinitions.has(tag)) ruleSetsDefinitions.set(tag, { tag, type: "remote", format: "binary", url: `https://gh.090227.xyz/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-${name}.srs`, download_detour: "DIRECT" });
                        return tag;
                    });
                    delete rule.geosite;
                }
                if (rule.geoip) {
                    const list = Array.isArray(rule.geoip) ? rule.geoip : [rule.geoip];
                    rule.rule_set = rule.rule_set || [];
                    list.forEach(name => {
                        const tag = `geoip-${name}`;
                        if (!ruleSetsDefinitions.has(tag)) ruleSetsDefinitions.set(tag, { tag, type: "remote", format: "binary", url: `https://gh.090227.xyz/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-${name}.srs`, download_detour: "DIRECT" });
                        rule.rule_set.push(tag);
                    });
                    delete rule.geoip;
                }
                const targetField = isDns ? 'server' : 'outbound';
                const actionValue = String(rule[targetField]).toUpperCase();
                if (actionValue === 'REJECT' || actionValue === 'BLOCK') {
                    rule.action = 'reject';
                    rule.method = 'drop';
                    delete rule[targetField];
                }
            });
        };
        if (config.dns && config.dns.rules) processRules(config.dns.rules, true);
        if (config.route && config.route.rules) processRules(config.route.rules, false);
        if (ruleSetsDefinitions.size > 0) {
            if (!config.route) config.route = {};
            config.route.rule_set = Array.from(ruleSetsDefinitions.values());
        }

        if (!config.outbounds) config.outbounds = [];
        config.outbounds = config.outbounds.filter(o => {
            if (o.tag === 'REJECT' || o.tag === 'block') return false;
            return true;
        });
        const existingTags = new Set(config.outbounds.map(o => o.tag));
        if (!existingTags.has('DIRECT')) { config.outbounds.push({ type: "direct", tag: "DIRECT" }); existingTags.add('DIRECT'); }

        if (config.dns && config.dns.servers) {
            const dnsTags = new Set(config.dns.servers.map(s => s.tag));
            if (config.dns.rules) {
                config.dns.rules.forEach(rule => {
                    if (rule.server && !dnsTags.has(rule.server)) {
                        if (rule.server === 'dns_block' && dnsTags.has('block')) rule.server = 'block';
                        else if (rule.server.toLowerCase().includes('block') && !dnsTags.has(rule.server)) {
                            config.dns.servers.push({ tag: rule.server, address: "rcode://success" });
                            dnsTags.add(rule.server);
                        }
                    }
                });
            }
        }

        config.outbounds.forEach(outbound => {
            if (outbound.type === 'selector' || outbound.type === 'urltest') {
                if (Array.isArray(outbound.outbounds)) {
                    outbound.outbounds = outbound.outbounds.filter(tag => {
                        const upper = tag.toUpperCase();
                        return existingTags.has(tag) && upper !== 'REJECT' && upper !== 'BLOCK';
                    });
                    if (outbound.outbounds.length === 0) outbound.outbounds.push("DIRECT");
                }
            }
        });

        if (uuid) {
            config.outbounds.forEach(outbound => {
                if ((outbound.uuid && outbound.uuid === uuid) || (outbound.password && outbound.password === uuid)) {
                    if (!outbound.tls) outbound.tls = { enabled: true };
                    if (fingerprint) outbound.tls.utls = { enabled: true, fingerprint };
                    if (ech_config) outbound.tls.ech = { enabled: true, config: `-----BEGIN ECH CONFIGS-----\n${ech_config}\n-----END ECH CONFIGS-----` };
                }
            });
        }
        return JSON.stringify(config, null, 2);
    } catch (e) {
        console.error("SingboxPatch Error:", e);
        return sb_json_text;
    }
}

export function ClashPatch(content, uuid, ECH, HOSTS, ECH_SNI, ECH_DNS) {
    let yaml = content.replace(/mode:\s*Rule\b/g, 'mode: rule');
    const baseDns = `dns:\n  enable: true\n  default-nameserver:\n    - 223.5.5.5\n    - 119.29.29.29\n    - 114.114.114.114\n  use-hosts: true\n  nameserver:\n    - https://sm2.doh.pub/dns-query\n    - https://dns.alidns.com/dns-query\n  fallback:${ECH_DNS ? `\n    - ${ECH_DNS}` : ''}\n    - 8.8.4.4\n    - 208.67.220.220\n  fallback-filter:\n    geoip: true\n    domain: [+.google.com, +.facebook.com, +.youtube.com]\n    ipcidr:\n      - 240.0.0.0/4\n      - 0.0.0.0/32\n    geoip-code: CN\n`;

    if (!/^dns:\s*(?:\n|$)/m.test(yaml)) yaml = baseDns + yaml;

    if (ECH_SNI && !HOSTS.includes(ECH_SNI)) HOSTS.push(ECH_SNI);
    if (ECH && HOSTS.length > 0) {
        const entries = HOSTS.map(host => `    "${host}":${ECH_DNS ? `\n      - ${ECH_DNS}` : ''}\n      - https://doh.cm.edu.kg/CMLiussss`).join('\n');
        if (/^\s{2}nameserver-policy:\s*(?:\n|$)/m.test(yaml)) {
            yaml = yaml.replace(/^(\s{2}nameserver-policy:\s*\n)/m, `$1${entries}\n`);
        } else {
            const nameserverPolicy = `  nameserver-policy:\n${entries}`;
            yaml += '\n' + nameserverPolicy;
        }
    }

    if (!uuid || !ECH) return yaml;

    const lines = yaml.split('\n');
    const processedLines = [];
    let i = 0;

    while (i < lines.length) {
        const line = lines[i];
        const trimmedLine = line.trim();

        if (trimmedLine.startsWith('- {') && (trimmedLine.includes('uuid:') || trimmedLine.includes('password:'))) {
            let fullNode = line;
            let braceCount = (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
            while (braceCount > 0 && i + 1 < lines.length) {
                i++;
                fullNode += '\n' + lines[i];
                braceCount += (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
            }
            const typeMatch = fullNode.match(/type:\s*(\w+)/);
            const proxyType = typeMatch ? typeMatch[1] : 'vless';
            let credentialField = 'uuid';
            if (proxyType === 'trojan') credentialField = 'password';
            const credentialPattern = new RegExp(`${credentialField}:\\s*([^,}\\n]+)`);
            const credentialMatch = fullNode.match(credentialPattern);
            if (credentialMatch && credentialMatch[1].trim() === uuid.trim()) {
                fullNode = fullNode.replace(/\}(\s*)$/, `, ech-opts: {enable: true${ECH_SNI ? `, query-server-name: ${ECH_SNI}` : ''}}}$1`);
            }
            processedLines.push(fullNode);
            i++;
        } else if (trimmedLine.startsWith('- name:')) {
            let nodeLines = [line];
            let baseIndent = line.search(/\S/);
            let topLevelIndent = baseIndent + 2;
            i++;
            while (i < lines.length) {
                const nextLine = lines[i];
                const nextTrimmed = nextLine.trim();
                if (!nextTrimmed) { nodeLines.push(nextLine); i++; break; }
                const nextIndent = nextLine.search(/\S/);
                if (nextIndent <= baseIndent && nextTrimmed.startsWith('- ')) break;
                if (nextIndent < baseIndent && nextTrimmed) break;
                nodeLines.push(nextLine);
                i++;
            }
            const nodeText = nodeLines.join('\n');
            const typeMatch = nodeText.match(/type:\s*(\w+)/);
            const proxyType = typeMatch ? typeMatch[1] : 'vless';
            let credentialField = 'uuid';
            if (proxyType === 'trojan') credentialField = 'password';
            const credentialPattern = new RegExp(`${credentialField}:\\s*([^\\n]+)`);
            const credentialMatch = nodeText.match(credentialPattern);
            if (credentialMatch && credentialMatch[1].trim() === uuid.trim()) {
                let insertIndex = -1;
                for (let j = nodeLines.length - 1; j >= 0; j--) {
                    if (nodeLines[j].trim()) { insertIndex = j; break; }
                }
                if (insertIndex >= 0) {
                    const indent = ' '.repeat(topLevelIndent);
                    const echOptsLines = [`${indent}ech-opts:`, `${indent}  enable: true`];
                    if (ECH_SNI) echOptsLines.push(`${indent}  query-server-name: ${ECH_SNI}`);
                    nodeLines.splice(insertIndex + 1, 0, ...echOptsLines);
                }
            }
            processedLines.push(...nodeLines);
        } else {
            processedLines.push(line);
            i++;
        }
    }
    return processedLines.join('\n');
}

export function SurgePatch(content, url, config) {
    let output = "";
    const realPath = config.启用0RTT ? config.PATH + '?ed=2560' : config.PATH;
    const lines = content.split(/\r?\n/);
    for (let x of lines) {
        if (x.includes('= trojan,') && !x.includes('ws=true') && !x.includes('ws-path=')) {
            const host = x.split("sni=")[1]?.split(",")[0];
            if (host) {
                const part = `sni=${host}, skip-cert-verify=${config.跳过证书验证}`;
                const correct = `sni=${host}, skip-cert-verify=${config.跳过证书验证}, ws=true, ws-path=${realPath}, ws-headers=Host:"${host}"`;
                output += x.replace(part, correct).replace("[", "").replace("]", "") + '\n';
            } else output += x + '\n';
        } else output += x + '\n';
    }
    output = `#!MANAGED-CONFIG ${url} interval=${config.优选订阅生成.SUBUpdateTime * 3600} strict=false` + output.substring(output.indexOf('\n'));
    return output;
}
