
import { MD5MD5 } from '../utils/helpers.js';

export async function checkAuth(request, env, config) {
    const cookies = request.headers.get('Cookie') || '';
    const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
    const UA = request.headers.get('User-Agent') || 'null';

    // config.UUID is userID, we need Admin password which is env.ADMIN/TOKEN etc.
    // Wait, in `_worker.js`:
    // const 管理员密码 = env.ADMIN || ... || env.uuid;
    // const 加密秘钥 = env.KEY || ...;
    // const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);

    // Config doesn't strictly store '管理员密码' raw. `checkAuth` needs it.
    // We should probably pass these env vars or calculated values.

    const adminPassword = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
    const secretKey = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';

    // logic: if (authCookie == await MD5MD5(UA + 加密秘钥 + 管理员密码))
    const expected = await MD5MD5(UA + secretKey + adminPassword);

    return authCookie === expected;
}

export async function handleLogin(request, env) {
    const adminPassword = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
    const secretKey = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
    const UA = request.headers.get('User-Agent') || 'null';

    if (request.method === 'POST') {
        const formData = await request.text();
        const params = new URLSearchParams(formData);
        const inputPassword = params.get('password');
        if (inputPassword === adminPassword) {
            const response = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
            const authValue = await MD5MD5(UA + secretKey + adminPassword);
            response.headers.set('Set-Cookie', `auth=${authValue}; Path=/; Max-Age=86400; HttpOnly`);
            return response;
        }
    }
    return fetch('https://edt-pages.github.io/login');
}

export async function handleLogout() {
    const response = new Response('Redirecting...', { status: 302, headers: { 'Location': '/login' } });
    response.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
    return response;
}
