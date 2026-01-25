# 🚀 EdgeTunnel (Refactored)

> **致敬与鸣谢**：
> 本项目核心代理逻辑参考自开源社区的杰出贡献。特别感谢：
> *   **cmliu** ([cmliu/edgetunnel](https://github.com/cmliu/edgetunnel)) - 原项目作者，提供了强大的面板与逻辑。
> *   **zizifn** ([zizifn/edgetunnel](https://github.com/zizifn/edgetunnel)) - 早期版本的贡献者。

---

> **EdgeTunnel (Refactored)** 是一个全新构建的 Cloudflare Workers 隧道代理方案。
> 它吸取了社区现有方案的设计思路，但采用**全模块化架构**从零重写，专为工程化部署和二次开发设计。

![Status](https://img.shields.io/badge/Status-Active-success)
![Author](https://img.shields.io/badge/Author-w0x7ce-blue)

---

## 📖 项目简介

这是一个运行在 Cloudflare 边缘网络上的轻量级隧道代理工具。

本项目对原有的单文件脚本进行了**彻底重构**，采用现代化的 **ESM 模块标准**，支持 **Wrangler CLI** 一键部署、本地调试以及 Git 版本管理。

它解耦了配置与核心逻辑，利用 **Cloudflare KV** 存储管理状态，并适配多种通信协议。旨在提供一个更符合工程化标准、易于扩展的 Serverless 网络编程范例，适合开发者学习 Worker 开发与 WebSocket 通信技术。

### ✨ 核心特性

- 🛡️ **协议支持**：支持 VLESS、Trojan 等主流协议。
- 📦 **模块化设计**：代码拆分为 `src/` 目录，职责分离（配置、逻辑、控制器），易于维护。
- 🛠 **工程化标准**：支持 `wrangler dev` 本地开发调试，告别在线编辑器的低效。
- 🔄 **订阅系统**：自动生成订阅链接，适配 Clash, Sing-box, Surge 等。
- ⚡ **性能优化**：利用 Cloudflare 全球边缘网络加速。

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
git clone https://github.com/tianrking/Re_edgetunnel.git
cd Re_edgetunnel
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

## ⚠️ 免责声明

本项目仅供技术研究与学习使用，请勿用于任何非法用途。作者不对使用本项目产生的任何后果负责。