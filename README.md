# 🚀 edgetunnel (Refactored by w0x7ce)

> 基于 Cloudflare Workers 的边缘计算隧道代理方案。  
> 本项目基于 [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) 进行现代化重构，支持 Wrangler CLI 开发与部署。

---

## 🛠 快速部署 (CLI)

请完全按照以下步骤进行部署。

### 1. 安装工具与登录
确保已有 Node.js 环境。

```bash
# 安装 Wrangler
npm install -g wrangler

# 登录 Cloudflare (浏览器授权)
npx wrangler login
```

### 2. 获取代码
```bash
git clone https://github.com/tianrking/edgetunnel
cd edgetunnel
```

### 3. 配置 KV 存储
创建一个 KV 命名空间用于存储配置：

```bash
npx wrangler kv namespace create edgetunnel
```

记下终端输出的 `id` (例如 `095b6650...`)，然后打开 `wrangler.toml` 文件，修改 `[[kv_namespaces]]` 部分：

```toml
[[kv_namespaces]]
binding = "KV"
id = "替换为你刚刚获取的ID"
```

### 4. 部署上线
```bash
npx wrangler deploy
```

部署成功后，控制台会显示 Worker 的访问网址（例如 `https://edgetunnel.xxx.workers.dev`）。

---

## ⚙️ 进阶配置

### 绑定自定义域名
在 `wrangler.toml` 中添加 `routes`：

```toml
routes = [
	{ pattern = "tunnel.your-domain.com", custom_domain = true }
]
```
重新部署：`npx wrangler deploy`

### 修改管理员密码 (UUID)
默认情况下，首次部署会自动生成随机 UUID。
如需固定，请在 `wrangler.toml` 的 `[vars]` 中设置：

```toml
[vars]
UUID = "你的UUID"
```

---

## 🫡 致敬与鸣谢

本项目由 **w0x7ce** 维护与重构，核心逻辑源自开源社区的杰出贡献。
特别感谢以下原作者与项目：

*   **cmliu** ([cmliu/edgetunnel](https://github.com/cmliu/edgetunnel)) - 原项目作者，提供了强大的面板与逻辑。
*   **zizifn** ([zizifn/edgetunnel](https://github.com/zizifn/edgetunnel)) - 早期版本的贡献者。
*   3Kmfi6HP, SHIJS1999, ACL4SSR 等社区贡献者。

---

## ⚠️ 免责声明

本项目仅供技术研究与学习使用，请勿用于任何非法用途。作者不对使用本项目产生的任何后果负责。