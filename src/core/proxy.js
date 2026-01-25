
import { connect } from "cloudflare:sockets";
import { parseVlessRequest, parseTrojanRequest } from "../protocols/parsers.js";
import { socks5Connect, httpConnect } from "../protocols/socks5.js";
import { base64ToArray, getSocks5Account } from "../utils/helpers.js";
import { parseProxyAddress } from "../utils/ip.js";

function closeSocketQuietly(socket) {
    try {
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
            socket.close();
        }
    } catch (error) { }
}

function isSpeedTestSite(hostname) {
    const speedTestDomains = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
    if (speedTestDomains.includes(hostname)) {
        return true;
    }

    for (const domain of speedTestDomains) {
        if (hostname.endsWith('.' + domain) || hostname === domain) {
            return true;
        }
    }
    return false;
}

function makeReadableStr(socket, earlyDataHeader) {
    let cancelled = false;
    return new ReadableStream({
        start(controller) {
            socket.addEventListener('message', (event) => {
                if (!cancelled) controller.enqueue(event.data);
            });
            socket.addEventListener('close', () => {
                if (!cancelled) {
                    closeSocketQuietly(socket);
                    controller.close();
                }
            });
            socket.addEventListener('error', (err) => controller.error(err));
            const { earlyData, error } = base64ToArray(earlyDataHeader);
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() {
            cancelled = true;
            closeSocketQuietly(socket);
        }
    });
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
    let header = headerData, hasData = false;
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            async write(chunk, controller) {
                hasData = true;
                if (webSocket.readyState !== WebSocket.OPEN) controller.error('ws.readyState is not open');
                if (header) {
                    const response = new Uint8Array(header.length + chunk.byteLength);
                    response.set(header, 0);
                    response.set(chunk, header.length);
                    webSocket.send(response.buffer);
                    header = null;
                } else {
                    webSocket.send(chunk);
                }
            },
            abort() { },
        })
    ).catch((err) => {
        closeSocketQuietly(webSocket);
    });
    if (!hasData && retryFunc) {
        await retryFunc();
    }
}

async function forwardDataUDP(udpChunk, webSocket, respHeader) {
    try {
        const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
        let vlessHeader = respHeader;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WebSocket.OPEN) {
                    if (vlessHeader) {
                        const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
                        response.set(vlessHeader, 0);
                        response.set(chunk, vlessHeader.length);
                        webSocket.send(response.buffer);
                        vlessHeader = null;
                    } else {
                        webSocket.send(chunk);
                    }
                }
            },
        }));
    } catch (error) {
        // console.error('UDP forward error:', error);
    }
}

async function forwardDataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID, proxyConfig) {
    // proxyConfig contains: proxyIP, enableProxyFallback, socks5 (type, account, global), whiteList
    // This is passed from the main worker to avoid global state issues.

    // unpack proxyConfig
    let {
        proxyIP,
        enableProxyFallback,
        socks5Type,
        socks5Account,
        socks5Global,
        socks5Whitelist,
        cachedProxyIndexRef // This is an object { value: 0 } so we can update it
    } = proxyConfig;

    // Note: parsedSocks5Address should be parsed once at request level if possible, 
    // or we parse it here if needed. Ideally passed in proxyConfig if it's static for the request.
    // Assuming socks5Account is the string.

    // console.log(`[TCP转发] 目标: ${host}:${portNum} | 反代IP: ${proxyIP} | ...`);

    async function connectDirect(address, port, data, proxyList = null, useFallback = true) {
        let remoteSock;
        if (proxyList && proxyList.length > 0) {
            for (let i = 0; i < proxyList.length; i++) {
                const idx = (cachedProxyIndexRef.value + i) % proxyList.length;
                const [pAddr, pPort] = proxyList[idx];
                try {
                    // console.log(`[反代连接] ...`);
                    remoteSock = connect({ hostname: pAddr, port: pPort });
                    await Promise.race([
                        remoteSock.opened,
                        new Promise((_, reject) => setTimeout(() => reject(new Error('连接超时')), 1000))
                    ]);
                    const testWriter = remoteSock.writable.getWriter();
                    await testWriter.write(data);
                    testWriter.releaseLock();
                    cachedProxyIndexRef.value = idx;
                    return remoteSock;
                } catch (err) {
                    try { remoteSock?.close?.(); } catch (e) { }
                    continue;
                }
            }
        }

        if (useFallback) {
            remoteSock = connect({ hostname: address, port: port });
            const writer = remoteSock.writable.getWriter();
            await writer.write(data);
            writer.releaseLock();
            return remoteSock;
        } else {
            closeSocketQuietly(ws);
            throw new Error('[反代连接] All proxy connections failed and fallback is disabled.');
        }
    }

    async function connectToProxy() {
        let newSocket;
        if (socks5Type === 'socks5') {
            const parsed = await getSocks5Account(socks5Account); // TODO: handle error or pre-parse
            newSocket = await socks5Connect(host, portNum, rawData, parsed);
        } else if (socks5Type === 'http' || socks5Type === 'https') {
            const parsed = await getSocks5Account(socks5Account);
            newSocket = await httpConnect(host, portNum, rawData, parsed);
        } else {
            const proxyList = await parseProxyAddress(proxyIP, host, yourUUID);
            newSocket = await connectDirect(atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg=='), 1, rawData, proxyList, enableProxyFallback);
        }
        remoteConnWrapper.socket = newSocket;
        newSocket.closed.catch(() => { }).finally(() => closeSocketQuietly(ws));
        connectStreams(newSocket, ws, respHeader, null);
    }

    const checkSocks5Whitelist = (addr) => socks5Whitelist.some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(addr));

    if (socks5Type && (socks5Global || checkSocks5Whitelist(host))) {
        await connectToProxy();
    } else {
        try {
            const initialSocket = await connectDirect(host, portNum, rawData);
            remoteConnWrapper.socket = initialSocket;
            connectStreams(initialSocket, ws, respHeader, connectToProxy);
        } catch (err) {
            await connectToProxy();
        }
    }
}

export async function handleWSRequest(request, yourUUID, proxyConfig) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStr(serverSock, earlyData);
    let isTrojan = null;

    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDnsQuery) return await forwardDataUDP(chunk, serverSock, null);
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            if (isTrojan === null) {
                const bytes = new Uint8Array(chunk);
                isTrojan = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a;
            }

            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            if (isTrojan) {
                const { port, hostname, rawClientData, hasError, message } = parseTrojanRequest(chunk, yourUUID);
                if (hasError) {
                    // console.error(message); 
                    return;
                }
                if (isSpeedTestSite(hostname)) return; // silently block?
                await forwardDataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper, yourUUID, proxyConfig);
            } else {
                const { port, hostname, rawIndex, version, isUDP, hasError, message } = parseVlessRequest(chunk, yourUUID);
                if (hasError) {
                    // console.error(message);
                    return;
                }
                if (isSpeedTestSite(hostname)) return;
                if (isUDP) {
                    if (port === 53) isDnsQuery = true;
                    else return; // throw new Error('UDP not supported');
                }
                const respHeader = new Uint8Array([version[0], 0]);
                const rawData = chunk.slice(rawIndex);
                if (isDnsQuery) return forwardDataUDP(rawData, serverSock, respHeader);
                await forwardDataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, yourUUID, proxyConfig);
            }
        },
    })).catch((err) => {
        // console.error('Pipe error', err);
    });

    return new Response(null, { status: 101, webSocket: clientSock });
}
