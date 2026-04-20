/**
 * AzureScan — 全局配置
 * 权重表、关键词库、阈值定义
 * 
 * ★ 核心设计原则：
 * 区分「合法开发工具」和「真正的风控风险项」
 * - VirtualBox Host-Only、ZeroTier、Radmin VPN = 合法工具，仅标记信息
 * - mihomo TUN、Clash TUN、WireGuard 隧道 = 代理风险，计入评分
 * - Parsec/Todesk/GameViewer 虚拟显卡 = 合法远程桌面工具，仅标记信息
 * - VMware SVGA、VBox Graphics = 真正的 VM GPU，计入评分
 */

import path from 'path';
import os from 'os';
import { CheckCategory, RiskLevel } from './types';

// ============================================================
// 版本
// ============================================================
export const VERSION = '3.0.1';
export const APP_NAME = 'AzureScan';

// ============================================================
// 路径
// ============================================================
export const PATHS = {
  /** 快照存储目录 */
  fingerprints: path.join(process.cwd(), 'fingerprints'),
  /** 报告输出目录 */
  reports: path.join(process.cwd(), 'reports'),
  /** 缓存目录 */
  cache: path.join(process.cwd(), '.cache'),
  /** HTML 模板 */
  templates: path.join(process.cwd(), 'templates'),
  /** 公共资源（GUI 前端） */
  public: path.join(process.cwd(), 'public'),
};

// ============================================================
// 类别权重乘数
// ============================================================
export const CATEGORY_WEIGHTS: Record<CheckCategory, number> = {
  [CheckCategory.CONSISTENCY]: 3.0,        // 一致性问题，最致命
  [CheckCategory.VIRTUALIZATION]: 2.5,      // 虚拟化/虚拟网卡
  [CheckCategory.NETWORK]: 2.5,            // 网络接口
  [CheckCategory.IP_TRANSPORT]: 2.0,       // IP/传输层
  [CheckCategory.BROWSER]: 2.0,            // 浏览器指纹
  [CheckCategory.SYSTEM]: 1.5,             // 系统硬件
  [CheckCategory.CLAUDE_SPECIFIC]: 1.5,    // Claude 专属
  [CheckCategory.BEHAVIORAL]: 1.0,         // 行为分析
  [CheckCategory.ADVANCED]: 1.0,           // 高阶预判
};

// ============================================================
// 风险等级阈值
// ============================================================
export const RISK_THRESHOLDS = {
  SAFE_MAX: 25,
  CAUTION_MAX: 50,
  HIGH_MAX: 75,
  // 76+ = CRITICAL
};

export function getRiskLevel(score: number): RiskLevel {
  if (score <= RISK_THRESHOLDS.SAFE_MAX) return RiskLevel.SAFE;
  if (score <= RISK_THRESHOLDS.CAUTION_MAX) return RiskLevel.CAUTION;
  if (score <= RISK_THRESHOLDS.HIGH_MAX) return RiskLevel.HIGH;
  return RiskLevel.CRITICAL;
}

export function getRiskColor(level: RiskLevel): string {
  switch (level) {
    case RiskLevel.SAFE: return '#22c55e';      // 绿
    case RiskLevel.CAUTION: return '#eab308';    // 黄
    case RiskLevel.HIGH: return '#f97316';       // 橙
    case RiskLevel.CRITICAL: return '#ef4444';   // 红
  }
}

export function getRiskLabel(level: RiskLevel): string {
  switch (level) {
    case RiskLevel.SAFE: return '极安全';
    case RiskLevel.CAUTION: return '建议优化';
    case RiskLevel.HIGH: return '高风险';
    case RiskLevel.CRITICAL: return '几乎必封';
  }
}

// ============================================================
// ★★★ 网卡/适配器分类体系 ★★★
// ============================================================

/**
 * 安全合法的网络适配器（开发工具、组网工具、远程桌面）
 * 这些适配器会被标记为「ℹ️ 信息」而非风险项，risk=0
 */
export const SAFE_ADAPTER_KEYWORDS = [
  // --- 组网/Mesh 工具（合法开发工具）---
  'zerotier',         // ZeroTier 组网
  'zerotier one',     // ZeroTier One 完整名
  'tailscale',        // Tailscale 组网
  'hamachi',          // Hamachi 组网
  'radmin vpn',       // Radmin VPN 组网
  'radmin',           // Radmin 系列工具

  // --- 虚拟化宿主机适配器（你是宿主机不是 VM）---
  'virtualbox host-only',  // VirtualBox Host-Only（宿主机端）
  'virtualbox host',       // VirtualBox Host 缩写
  'vmware network',        // VMware 宿主机桥接
  'vmware virtual ethernet', // VMware 虚拟以太网（宿主机侧）
  'hyper-v virtual ethernet', // Hyper-V 管理网卡
  'hyper-v virtual switch',   // Hyper-V 虚拟交换机

  // --- 系统内置 ---
  'loopback',           // 回环接口，固有
  'pseudo-interface',   // Windows 伪接口
  'isatap',             // Windows ISATAP 隧道适配器
  'teredo',             // Windows Teredo 隧道
  '6to4',               // IPv6 过渡隧道
  'kdnet',              // 内核调试网络

  // --- 容器开发工具 ---
  'docker',           // Docker 网络
  'veth',             // Docker/容器虚拟 Ethernet
  'br-',              // Docker 桥接
  'podman',           // Podman 容器

  // --- 远程桌面/串流工具 ---
  'parsec',           // Parsec 远程串流
  'todesk',           // ToDesk 远程桌面
  'rustdesk',         // RustDesk 远程桌面
  'anydesk',          // AnyDesk 远程桌面
  'teamviewer',       // TeamViewer 远程桌面

  // --- 其他合法工具 ---
  'npcap',            // Wireshark 抓包适配器
  'winpcap',          // 旧版抓包适配器
  'sangfor',          // 深信服 VPN 企业级
];

/**
 * ★ 真正的代理/VPN 隧道适配器（高风险，直接影响流量出口）
 * 这些适配器意味着你的流量正在被代理/VPN 路由
 */
export const PROXY_TUN_KEYWORDS = [
  // --- 代理软件 TUN 适配器（★ 最高风险） ---
  'mihomo',           // mihomo (Clash Meta) TUN
  'clash',            // Clash TUN
  'clash meta',       // Clash Meta TUN 精确匹配
  'clash.meta',       // Clash.Meta 变体
  'sing-box',         // sing-box TUN
  'singbox',          // sing-box 无连字符变体
  'tun2socks',        // tun2socks
  'hev-socks5',       // hev-socks5-tunnel
  'utun',             // mihomo/sing-box 常用 TUN 接口名

  // --- 代理通用 TUN 驱动 ---
  'wintun userspace tunnel',  // Wintun 完整接口描述
  'wintun',           // WireGuard/代理通用 TUN 驱动

  // --- 商业 VPN TUN（高风险，暴露 VPN 使用）---
  'nordlynx',         // NordVPN
  'proton',           // ProtonVPN
  'mullvad',          // Mullvad
  'expressvpn',       // ExpressVPN
  'surfshark',        // Surfshark
  'windscribe',       // Windscribe
  'astrill',          // Astrill VPN
  'cyberghost',       // CyberGhost VPN

  // --- VPN 协议隧道 ---
  'openvpn',          // OpenVPN TAP/TUN
  'tap-windows',      // OpenVPN TAP 适配器
  'softether',        // SoftEther
  'pptp',             // PPTP
  'l2tp',             // L2TP
  'sstp',             // SSTP
  'wireguard',        // WireGuard
];

/**
 * ★ 代理软件进程名（检测正在运行的代理）
 * 这些是真正影响流量的代理软件
 */
export const PROXY_PROCESS_NAMES = [
  // --- 核心代理内核（★ 最高风险）---
  'mihomo', 'mihomo.exe',
  'clash', 'clash.exe', 'clash-meta', 'clash-meta.exe',
  'v2ray', 'v2ray.exe',
  'xray', 'xray.exe',
  'sing-box', 'sing-box.exe',
  'hysteria', 'hysteria.exe',
  'hysteria2',
  'naiveproxy', 'naive', 'naive.exe',
  'trojan', 'trojan-go', 'trojan.exe',
  'shadowsocks', 'ss-local', 'sslocal',
  'brook',
  'gost',
  'tuic',

  // --- 代理客户端 GUI ---
  'clash-verge', 'clashverge',
  'clash-nyanpasu', 'clashnyanpasu',
  'v2rayn', 'v2rayn.exe',
  'v2raya',
  'nekoray', 'nekobox',
  'hiddify',
  'surfboard',
  'quantumult',
  'shadowrocket',
];

/**
 * 合法的 VPN/组网工具进程（不计入风险评分）
 */
export const SAFE_VPN_PROCESS_NAMES = [
  'zerotier', 'zerotier-one', 'zerotier_desktop', 'zerotier-one_x64',
  'tailscale', 'tailscaled', 'tailscale-ipn',
  'radmin', 'rvpn', 'radminvpn',
  'hamachi', 'hamachi-2', 'logmein',
  'parsec', 'parsecd', 'pservice',  // Parsec 远程串流
  'todesk', 'todeskservice',        // ToDesk 远程桌面
  'rustdesk',                        // RustDesk 远程桌面
  'anydesk', 'anydeskservice',       // AnyDesk 远程桌面
  'teamviewer', 'teamviewerservice', // TeamViewer 远程桌面
];

// ============================================================
// ★★★ GPU/显卡分类体系 ★★★
// ============================================================

/**
 * 合法的远程桌面/串流虚拟显卡（不计入风险评分）
 */
export const SAFE_VIRTUAL_GPU_KEYWORDS = [
  'parsec',           // Parsec 远程串流
  'todesk',           // ToDesk 远程桌面
  'gameviewer',       // GameViewer 远程
  'sunshine',         // Sunshine 串流
  'moonlight',        // Moonlight 串流
  'rustdesk',         // RustDesk 远程
  'anydesk',          // AnyDesk 远程
  'teamviewer',       // TeamViewer 远程
  'spacedesk',        // SpaceDesk 扩展屏
  'duet display',     // Duet Display 扩展屏
  'displaylink',      // DisplayLink USB 显示
  'usbmmidd',         // USB 虚拟显示
  'indirect display', // Windows IDD 虚拟显示
];

/**
 * ★ 真正的 VM 虚拟 GPU（高风险，说明运行在虚拟机内）
 */
export const VM_GPU_KEYWORDS = [
  'vmware svga',
  'vmware virtual',
  'virtualbox graphics',
  'vbox vga',
  'qxl',
  'red hat virtio',
  'red hat qxl',
  'hyper-v video',
  'microsoft basic display',   // 仅在 VM 内是风险
  'microsoft remote display',
  'parallels display',
  'cirrus logic',
  'bochs',
  'spice',
];

// ============================================================
// ★★★ 虚拟化驱动分类 ★★★
// ============================================================

/**
 * 合法的驱动关键词白名单（不计入虚拟化风险）
 */
export const SAFE_DRIVER_KEYWORDS = [
  // --- 远程桌面/串流虚拟显卡驱动 ---
  'parsec', 'parsecvda', 'parsec virtual display',
  'todesk', 'todeskid', 'todesk virtual display',
  'gameviewer', 'gamevieweridd', 'gameviewer virtual display',
  'sunshine', 'sunshinehd', 'sunshine virtual display',
  'moonlight',
  'rustdesk', 'rustdeskvirtualdisplay',
  'anydesk', 'anydesknet',
  'teamviewer', 'teamviewervpn',
  'spacedesk', 'spacedeskidd',
  'indirect display', // IDD 类通用虚拟显示驱动
  'iddsampledriver',  // IDD 示例驱动

  // --- 组网/VPN 工具驱动 ---
  'zerotier', 'ztnetwork',
  'tailscale', 'tswintun',
  'radmin', 'radminvpn',
  'hamachi',

  // --- 抓包/网络分析 ---
  'npcap', 'npcaphelper',
  'winpcap',

  // --- 显示扩展 ---
  'usbmmidd',
  'displaylink',

  // --- VirtualBox 宿主机侧驱动（非 Guest）---
  'virtualbox host',
  'vboxnetadp',       // VBox Host-Only 网络适配器驱动
  'vboxnetflt',       // VBox 桥接网络过滤驱动
  'vboxnetlwf',       // VBox 网络 LWF 驱动
  'vboxsup',          // VBox 支持驱动 (宿主机)
  'vboxusb',          // VBox USB 驱动 (宿主机)
  'vboxdrv',          // VBox 主驱动 (宿主机)

  // --- VMware 宿主机侧驱动 ---
  // ★ 注意：不能用宽泛的 'vmware'，否则会误匹配 VM Guest 驱动（vmci, vmhgfs 等）
  'vmnetadapter',     // VMware 网络适配器
  'vmnetbridge',      // VMware 桥接
  'vmnetuserif',      // VMware UserIf
  'vmparport',        // VMware 并行端口
  'vmware workstation', // VMware Workstation 宿主进程
  'vmware player',      // VMware Player 宿主进程
  'vmware authd',       // VMware 认证服务
  'vmx86',              // VMware x86 虚拟化引擎
  'vmkbd',              // VMware 键盘驱动
];

/**
 * ★ 真正的虚拟化驱动（说明运行在 VM 内）
 */
export const VM_DRIVER_KEYWORDS = [
  'vboxguest', 'vboxmouse', 'vboxsf', 'vboxvideo',  // VBox Guest
  'vmci', 'vmhgfs', 'vmmouse', 'vmrawdsk', 'vmxnet', // VMware Guest
  'vioscsi', 'viostor', 'vioserial', 'vioinput',      // VirtIO (KVM)
  'netkvm',                                            // KVM 网络
  'balloon',                                           // 内存 balloon
  'pvpanic',                                           // KVM panic
  'xen',                                               // Xen
  'virtio',                                            // VirtIO 通用
];

// ============================================================
// MAC OUI 前缀 → 虚拟化厂商
// ============================================================
export const MAC_OUI_PREFIXES: Record<string, { vendor: string; risk: boolean }> = {
  // ★ 这些 OUI 只在你运行在 VM 内部时才是风险
  // 如果你是宿主机 + VBox Host-Only，这个 MAC 是安全的
  '00:0C:29': { vendor: 'VMware (Guest)', risk: true },
  '00:50:56': { vendor: 'VMware (Guest)', risk: true },
  '00:05:69': { vendor: 'VMware (Guest)', risk: true },
  '08:00:27': { vendor: 'VirtualBox (Guest)', risk: true },
  '0A:00:27': { vendor: 'VirtualBox (Host-Only)', risk: false },  // ★ Host-Only = 安全
  '00:15:5D': { vendor: 'Hyper-V', risk: true },
  '52:54:00': { vendor: 'KVM/QEMU', risk: true },
  '00:16:3E': { vendor: 'Xen', risk: true },
  '02:42:AC': { vendor: 'Docker', risk: false },  // Docker 网络 = 开发工具
  '02:42:00': { vendor: 'Docker', risk: false },
  '00:1C:42': { vendor: 'Parallels', risk: true },
};

// ============================================================
// VM 检测特征文件/注册表路径（Windows）
// ============================================================
export const VM_ARTIFACTS = {
  windows: {
    files: [
      'C:\\Program Files\\VMware\\VMware Tools',
      'C:\\Program Files\\Oracle\\VirtualBox Guest Additions',
      'C:\\Windows\\System32\\drivers\\vmmouse.sys',
      'C:\\Windows\\System32\\drivers\\vmhgfs.sys',
      'C:\\Windows\\System32\\drivers\\VBoxMouse.sys',
      'C:\\Windows\\System32\\drivers\\VBoxGuest.sys',
      'C:\\Windows\\System32\\drivers\\VBoxSF.sys',
    ],
    registryKeys: [
      'HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools',
      'HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions',
      'HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__',
      'HKLM\\HARDWARE\\ACPI\\FADT\\VBOX__',
      'HKLM\\SYSTEM\\CurrentControlSet\\Services\\VBoxGuest',
      'HKLM\\SYSTEM\\CurrentControlSet\\Services\\vmci',
    ],
    processes: [
      'vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe',
      'VBoxTray.exe', 'VBoxService.exe',
    ],
    services: [
      'VMTools', 'VMware Physical Disk Helper Service',
      'VBoxService', 'VBoxGuest',
    ],
  },
};

// ============================================================
// 已知的浏览器 JA4 指纹签名（用于比对）
// ============================================================
export const KNOWN_JA4_SIGNATURES: Record<string, string> = {
  'Chrome_Windows': 't13d1516h2_8daaf6152771_e5627efa2ab1',
  'Firefox_Windows': 't13d1517h2_8daaf6152771_3b2c3fafb4fd',
  'Edge_Windows': 't13d1516h2_8daaf6152771_e5627efa2ab1',
};

// ============================================================
// IP 查询 API
// ============================================================
export const IP_API = {
  url: 'http://ip-api.com/json/?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,proxy,hosting,query',
  cacheFile: path.join(process.cwd(), '.cache', 'ip-cache.json'),
  cacheTTL: 3600000, // 1 小时
};

// ============================================================
// GUI 服务器
// ============================================================
export const SERVER = {
  port: 3847,
  host: 'localhost',
};

// ============================================================
// Claude 配置路径
// ============================================================
export const CLAUDE_CONFIG_PATH = path.join(os.homedir(), '.claude', 'config.json');
