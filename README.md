# 🛡️ AzureScan

**AI平台环境指纹自检工具** — 本地环境风控自查

> 纯本地运行，无数据上传。检测 150+ 项指纹与遥测信号，覆盖 Claude、OpenAI、Gemini 等主流 AI 平台的已知检测点。

## ✨ 功能

- **🌐 网络检测** — 虚拟网卡、MAC OUI、VPN/代理进程、DNS 配置
- **💻 系统硬件** — CPU/GPU/RAM/BIOS 虚拟化标记检测
- **🖥️ 虚拟化检测** — VMware/VirtualBox/Hyper-V/Docker/WSL 特征
- **📡 IP & 传输层** — IP 地理位置、代理检测、数据中心 ASN、时区一致性
- **🔍 浏览器指纹** — Canvas/WebGL/AudioContext/Navigator 60+ 项 JS 指纹
- **🔗 一致性检查** — 跨模块交叉验证（×3 权重），最致命的检测维度
- **🤖 Claude 专属** — Device ID、遥测数据预览、SSH/WSL 环境
- **📊 风险评分** — 加权评分算法，0-100 分 + 颜色等级
- **📄 多格式报告** — HTML 仪表盘 + Markdown + JSON
- **📸 快照对比** — 历史指纹对比，验证修复效果
- **🌐 Web GUI** — 浏览器可视化操作界面

## 🚀 快速开始

### 安装

```bash
cd AzureScan
npm install
```

### CLI 使用

```bash
# 快速扫描（跳过浏览器指纹）
npx ts-node src/main.ts

# 完整扫描（含浏览器指纹，需要 Playwright）
npx ts-node src/main.ts --full

# 生成 HTML 报告并自动打开
npx ts-node src/main.ts --full --html

# 保存快照
npx ts-node src/main.ts --save-snapshot

# 与上次快照对比
npx ts-node src/main.ts --compare

# 查看帮助
npx ts-node src/main.ts --help
```

### Web GUI

```bash
# 启动 Web 界面
npx ts-node src/server.ts

# 或使用 npm 脚本
npm run gui
```

浏览器自动打开 `http://localhost:3847`，点击「快速扫描」即可。

### Playwright（可选，用于浏览器指纹）

```bash
npm install playwright
npx playwright install chromium
```

## 📊 风险等级

| 分数 | 等级 | 颜色 | 说明 |
|------|------|------|------|
| 0-25 | 极安全 | 🟢 | 环境干净 |
| 26-50 | 建议优化 | 🟡 | 存在可优化项 |
| 51-75 | 高风险 | 🟠 | 多项异常，建议修复 |
| 76-100 | 几乎必封 | 🔴 | 严重风险，必须修复 |

## 📁 项目结构

```
AzureScan/
├── src/
│   ├── main.ts              # CLI 入口
│   ├── server.ts            # Web GUI 服务器
│   ├── scanner.ts           # 扫描引擎
│   ├── config.ts            # 全局配置
│   ├── types/index.ts       # TypeScript 类型定义
│   ├── modules/
│   │   ├── network.ts       # 网络接口检测
│   │   ├── system.ts        # 系统硬件检测
│   │   ├── virtualization.ts # 虚拟化检测
│   │   ├── browser.ts       # 浏览器指纹
│   │   ├── ip-transport.ts  # IP & 传输层
│   │   ├── consistency.ts   # 一致性检查
│   │   └── claude-specific.ts # Claude 专属
│   └── utils/
│       ├── helpers.ts        # 工具函数
│       ├── risk-scorer.ts    # 风险评分
│       ├── report-generator.ts # 报告生成
│       └── snapshot.ts       # 快照管理
├── public/
│   └── index.html           # Web GUI 前端
├── reports/                  # 生成的报告
├── fingerprints/             # 快照文件
└── package.json
```

## ⚠️ 免责声明

本工具仅用于自我环境检测和安全评估，帮助用户了解自身环境的指纹特征。请遵守相关平台的使用条款。

## 📝 License

MIT
