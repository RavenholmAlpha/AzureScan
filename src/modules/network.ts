/**
 * AzureScan — 网络接口 & 虚拟适配器检测模块
 * ★ 最高优先级模块
 * 
 * ★ 核心分类逻辑：
 * 1. 代理/VPN TUN 适配器（mihomo、Clash、WireGuard）→ 高风险，计入评分
 * 2. 合法开发工具（VirtualBox Host-Only、ZeroTier、Radmin VPN、Docker）→ 仅标记信息，risk=0
 * 3. 物理网卡 → 正常，risk=0
 * 4. 代理软件进程（mihomo、v2ray、xray、sing-box）→ 高风险
 * 5. 合法 VPN 进程（ZeroTier、Tailscale）→ 仅标记信息
 * 
 * ★ v3.1 改进：
 * - 使用 Get-NetAdapter 获取 InterfaceDescription 做双源检测
 * - os.networkInterfaces() 返回「连接名称」（如 "以太网"）
 * - Get-NetAdapter 返回「接口描述」（如 "Mihomo TUN", "Intel Wi-Fi 6"）
 * - 两者联合匹配，彻底解决 mihomo TUN 等适配器漏检问题
 */

import os from 'os';
import { CheckCategory, CheckItem, ModuleResult, ScanModule } from '../types';
import {
  SAFE_ADAPTER_KEYWORDS,
  PROXY_TUN_KEYWORDS,
  PROXY_PROCESS_NAMES,
  SAFE_VPN_PROCESS_NAMES,
  MAC_OUI_PREFIXES,
  CATEGORY_WEIGHTS,
} from '../config';
import {
  execCommand,
  execPowerShell,
  IS_WINDOWS,
  normalizeMac,
  getOUI,
  createCheckItem,
  Timer,
  safeJsonParse,
} from '../utils/helpers';

/** 适配器分类结果 */
type AdapterClass = 'physical' | 'safe_tool' | 'proxy_tun' | 'unknown_virtual';

/** Windows Get-NetAdapter 返回的适配器信息 */
interface NetAdapterInfo {
  Name: string;                   // 连接名称（与 os.networkInterfaces() key 对应）
  InterfaceDescription: string;   // ★ 接口描述（硬件/驱动名称，如 "Mihomo TUN", "Intel Wi-Fi"）
  Status: string;                 // Up / Disconnected / Not Present
  MacAddress: string;
  InterfaceIndex: number;
}

export class NetworkModule implements ScanModule {
  name = '网络接口 & 虚拟适配器';
  category = CheckCategory.NETWORK;

  async run(): Promise<ModuleResult> {
    const timer = new Timer();
    const items: CheckItem[] = [];
    const weight = CATEGORY_WEIGHTS[this.category];

    try {
      const interfaces = os.networkInterfaces();
      const interfaceNames = Object.keys(interfaces);

      // ----------------------------------------------------------
      // 0. ★ 获取 Windows 适配器详细描述（InterfaceDescription）
      // ----------------------------------------------------------
      const adapterDescMap = IS_WINDOWS ? this.getAdapterDescriptions() : new Map<string, string>();

      // ----------------------------------------------------------
      // 1. 分类所有网络接口（★ 双源匹配：连接名 + 接口描述）
      // ----------------------------------------------------------
      const classified: Array<{ name: string; cls: AdapterClass; matchedKeyword?: string; description?: string }> = [];

      for (const name of interfaceNames) {
        const description = adapterDescMap.get(name) || '';
        const cls = this.classifyAdapter(name, description);
        classified.push({ ...cls, description });
      }

      // ★ 补充检测：Get-NetAdapter 中有而 os.networkInterfaces() 中没有的适配器
      // （某些 TUN 适配器可能不在 os.networkInterfaces() 结果中）
      for (const [adapterName, desc] of adapterDescMap) {
        if (!interfaceNames.includes(adapterName)) {
          const cls = this.classifyAdapter(adapterName, desc);
          if (cls.cls === 'proxy_tun') {
            classified.push({ ...cls, description: desc });
          }
        }
      }

      const proxyTunAdapters = classified.filter(c => c.cls === 'proxy_tun');
      const safeToolAdapters = classified.filter(c => c.cls === 'safe_tool');
      const physicalAdapters = classified.filter(c => c.cls === 'physical');
      const unknownVirtual = classified.filter(c => c.cls === 'unknown_virtual');

      // 总接口数（信息项）
      items.push(createCheckItem(
        'network.interface_count',
        '网络接口总数',
        this.category,
        { total: interfaceNames.length, physical: physicalAdapters.length, safe_tools: safeToolAdapters.length, proxy_tun: proxyTunAdapters.length },
        0, // 接口数本身不是风险
        weight,
        `共 ${interfaceNames.length} 个接口 (物理:${physicalAdapters.length} 开发工具:${safeToolAdapters.length} 代理TUN:${proxyTunAdapters.length})`,
      ));

      // ----------------------------------------------------------
      // 2. ★ 代理/VPN TUN 适配器（真正的风险项）
      // ----------------------------------------------------------
      if (proxyTunAdapters.length > 0) {
        items.push(createCheckItem(
          'network.proxy_tun_count',
          '⚠️ 代理/VPN TUN 适配器',
          this.category,
          proxyTunAdapters.map(a => a.name),
          Math.min(9, 6 + proxyTunAdapters.length),
          weight,
          `检测到 ${proxyTunAdapters.length} 个代理/VPN TUN 适配器: ${proxyTunAdapters.map(a => a.name).join(', ')}`,
          '使用 AI 平台前关闭代理软件的 TUN 模式，或切换为系统代理模式',
          '★ TUN 适配器直接接管系统全部流量，是平台检测代理的最强信号',
        ));

        // 每个代理 TUN 适配器的详情
        for (const adapter of proxyTunAdapters) {
          const descStr = adapter.description ? ` [描述: ${adapter.description}]` : '';
          items.push(createCheckItem(
            `network.proxy_tun.${adapter.name.replace(/[^a-z0-9]/gi, '_')}`,
            `代理 TUN: ${adapter.name}`,
            this.category,
            { name: adapter.name, matched: adapter.matchedKeyword, description: adapter.description },
            8,
            weight,
            `代理/VPN TUN 适配器「${adapter.name}」(匹配: ${adapter.matchedKeyword})${descStr}`,
            `关闭对应的代理软件或禁用 TUN 模式`,
            '代理 TUN 适配器是流量劫持的直接证据',
          ));
        }
      } else {
        items.push(createCheckItem(
          'network.proxy_tun_count',
          '代理/VPN TUN 适配器',
          this.category,
          '未检测到',
          0,
          weight,
          '未检测到代理/VPN TUN 适配器 ✓',
        ));
      }

      // ----------------------------------------------------------
      // 3. 合法开发工具适配器（仅信息，risk=0）
      // ----------------------------------------------------------
      if (safeToolAdapters.length > 0) {
        items.push(createCheckItem(
          'network.safe_tools',
          'ℹ️ 开发工具适配器',
          this.category,
          safeToolAdapters.map(a => `${a.name} (${a.matchedKeyword})`),
          0,              // ★ 不计入风险
          weight,
          `${safeToolAdapters.length} 个合法开发工具适配器: ${safeToolAdapters.map(a => a.name).join(', ')}`,
          undefined,
          '这些是合法的开发/组网工具，不影响风控评分',
        ));
      }

      // ----------------------------------------------------------
      // 4. 未分类的虚拟适配器（中等风险，需人工判断）
      // ----------------------------------------------------------
      if (unknownVirtual.length > 0) {
        items.push(createCheckItem(
          'network.unknown_virtual',
          '未分类虚拟适配器',
          this.category,
          unknownVirtual.map(a => ({ name: a.name, description: a.description })),
          unknownVirtual.length > 2 ? 4 : 2,
          weight,
          `${unknownVirtual.length} 个未分类虚拟适配器: ${unknownVirtual.map(a => {
            const desc = a.description ? ` [${a.description}]` : '';
            return `${a.name}${desc}`;
          }).join(', ')}`,
          '如非必需，考虑禁用这些适配器',
          '无法自动确定这些适配器的用途，建议人工检查',
        ));
      }

      // ----------------------------------------------------------
      // 5. MAC OUI 前缀匹配（区分宿主机 vs VM 内部）
      // ----------------------------------------------------------
      for (const [ifName, addrs] of Object.entries(interfaces)) {
        if (!addrs) continue;
        for (const addr of addrs) {
          if (addr.mac === '00:00:00:00:00:00') continue;
          const oui = getOUI(addr.mac);
          const ouiInfo = MAC_OUI_PREFIXES[oui];
          if (ouiInfo) {
            const description = adapterDescMap.get(ifName) || '';
            const adapterClass = this.classifyAdapter(ifName, description);
            // 如果适配器本身是安全工具（如 VBox Host-Only），MAC OUI 也不应计分
            const isRisk = ouiInfo.risk && adapterClass.cls !== 'safe_tool';
            
            items.push(createCheckItem(
              `network.mac_oui.${ifName.replace(/[^a-z0-9]/gi, '_')}`,
              isRisk ? `⚠️ MAC OUI: ${ouiInfo.vendor}` : `ℹ️ MAC OUI: ${ouiInfo.vendor}`,
              this.category,
              { interface: ifName, mac: normalizeMac(addr.mac), vendor: ouiInfo.vendor },
              isRisk ? 7 : 0,    // ★ 安全适配器的 MAC 不计分
              weight,
              isRisk
                ? `接口「${ifName}」MAC ${normalizeMac(addr.mac)} 属于 ${ouiInfo.vendor}`
                : `接口「${ifName}」MAC ${normalizeMac(addr.mac)} 属于 ${ouiInfo.vendor}（合法工具，不计分）`,
              isRisk ? '更改 MAC 地址或确认是否在虚拟机内' : undefined,
              isRisk ? 'MAC OUI 暴露虚拟化环境' : '此 MAC 属于已知安全工具',
            ));
          }
        }
      }

      // ----------------------------------------------------------
      // 6. ★ 代理软件进程检测（关键检测项）
      // ----------------------------------------------------------
      if (IS_WINDOWS) {
        const taskList = execCommand('tasklist /FO CSV /NH').toLowerCase();
        const runningProxies: string[] = [];
        const runningSafeVpns: string[] = [];

        // 检测代理进程（★ 高风险）
        for (const proc of PROXY_PROCESS_NAMES) {
          if (taskList.includes(proc.toLowerCase())) {
            // 避免重复（exe 和非 exe 名称）
            const baseName = proc.replace(/\.exe$/i, '');
            if (!runningProxies.includes(baseName)) {
              runningProxies.push(baseName);
            }
          }
        }

        // 检测合法 VPN 进程（仅信息）
        for (const proc of SAFE_VPN_PROCESS_NAMES) {
          if (taskList.includes(proc.toLowerCase())) {
            const baseName = proc.replace(/\.exe$/i, '');
            if (!runningSafeVpns.includes(baseName)) {
              runningSafeVpns.push(baseName);
            }
          }
        }

        // 代理进程 → 高风险
        items.push(createCheckItem(
          'network.proxy_processes',
          runningProxies.length > 0 ? '⚠️ 代理软件进程' : '代理软件进程',
          this.category,
          runningProxies.length > 0 ? runningProxies : '未检测到',
          runningProxies.length > 0 ? Math.min(9, 6 + runningProxies.length) : 0,
          weight,
          runningProxies.length > 0
            ? `★ 检测到代理软件进程: ${runningProxies.join(', ')}`
            : '未检测到代理软件进程 ✓',
          runningProxies.length > 0 ? '使用 AI 平台前关闭代理软件' : undefined,
          '代理软件进程是流量劫持的直接证据，平台可通过进程列表检测',
        ));

        // 合法 VPN 进程 → 仅信息
        if (runningSafeVpns.length > 0) {
          items.push(createCheckItem(
            'network.safe_vpn_processes',
            'ℹ️ 合法组网工具进程',
            this.category,
            runningSafeVpns,
            0,
            weight,
            `合法组网工具进程: ${runningSafeVpns.join(', ')}`,
            undefined,
            '这些是合法的组网工具，不影响风控评分',
          ));
        }
      }

      // ----------------------------------------------------------
      // 7. ★ Wintun 驱动检测（mihomo/Clash TUN 的底层驱动）
      // ----------------------------------------------------------
      if (IS_WINDOWS) {
        const wintunDriver = execCommand('driverquery /FO CSV /NH').toLowerCase();
        const hasWintun = wintunDriver.includes('wintun');
        
        if (hasWintun) {
          items.push(createCheckItem(
            'network.wintun_driver',
            '⚠️ Wintun TUN 驱动',
            this.category,
            '已安装',
            5,
            weight,
            'Wintun TUN 驱动已安装（mihomo/Clash/WireGuard 等代理软件使用的 TUN 驱动）',
            '如不需要 TUN 模式，可卸载 Wintun 驱动',
            'Wintun 是代理软件 TUN 模式的底层驱动，安装即暗示代理使用',
          ));
        }
      }

      // ----------------------------------------------------------
      // 8. 代理环境变量检测
      // ----------------------------------------------------------
      const proxyEnvVars = ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'];
      const setProxies: Record<string, string> = {};
      for (const envVar of proxyEnvVars) {
        const val = process.env[envVar];
        if (val) setProxies[envVar] = val;
      }

      items.push(createCheckItem(
        'network.proxy_env',
        Object.keys(setProxies).length > 0 ? '⚠️ 代理环境变量' : '代理环境变量',
        this.category,
        Object.keys(setProxies).length > 0 ? setProxies : '未设置',
        Object.keys(setProxies).length > 0 ? 6 : 0,
        weight,
        Object.keys(setProxies).length > 0
          ? `检测到代理环境变量: ${Object.entries(setProxies).map(([k,v]) => `${k}=${v}`).join(', ')}`
          : '未检测到代理环境变量 ✓',
        Object.keys(setProxies).length > 0 ? '使用前清除: unset HTTP_PROXY HTTPS_PROXY ALL_PROXY' : undefined,
        '代理环境变量是代理使用的直接证据',
      ));

      // ----------------------------------------------------------
      // 9. Windows 系统代理设置
      // ----------------------------------------------------------
      if (IS_WINDOWS) {
        const proxyEnabled = execCommand(
          'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable'
        );
        const proxyServer = execCommand(
          'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyServer'
        );

        const isProxyEnabled = proxyEnabled.includes('0x1');
        const proxyAddr = proxyServer.match(/ProxyServer\s+REG_SZ\s+(.+)/)?.[1]?.trim();

        items.push(createCheckItem(
          'network.system_proxy',
          isProxyEnabled ? '⚠️ 系统代理' : '系统代理',
          this.category,
          isProxyEnabled ? (proxyAddr || '已启用') : '未启用',
          isProxyEnabled ? 5 : 0,
          weight,
          isProxyEnabled
            ? `系统代理已启用: ${proxyAddr || '未知地址'}`
            : '系统代理未启用 ✓',
          isProxyEnabled ? '设置 → 网络 → 代理 中关闭' : undefined,
          '系统代理设置暴露代理使用',
        ));
      }

      // ----------------------------------------------------------
      // 10. DNS 配置（信息项）
      // ----------------------------------------------------------
      if (IS_WINDOWS) {
        const dnsOutput = execCommand('ipconfig /all');
        const dnsServers: string[] = [];
        const dnsRegex = /DNS Servers[\s.]*:\s*([\d.]+)/gi;
        let match;
        while ((match = dnsRegex.exec(dnsOutput)) !== null) {
          dnsServers.push(match[1]);
        }

        items.push(createCheckItem(
          'network.dns_config',
          'DNS 配置',
          this.category,
          dnsServers.length > 0 ? dnsServers : '无法获取',
          0,
          weight,
          dnsServers.length > 0 ? `DNS: ${dnsServers.join(', ')}` : '无法获取 DNS 配置',
        ));
      }

      // ----------------------------------------------------------
      // 计算模块风险分
      // ----------------------------------------------------------
      const totalRisk = this.calculateModuleRisk(items);

      return {
        moduleName: this.name,
        category: this.category,
        items,
        risk: totalRisk,
        summary: this.generateSummary(items, proxyTunAdapters.length),
        duration: timer.elapsed(),
        success: true,
      };
    } catch (error: any) {
      return {
        moduleName: this.name,
        category: this.category,
        items,
        risk: 0,
        summary: `模块执行出错: ${error.message}`,
        duration: timer.elapsed(),
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * ★ 获取 Windows 适配器接口描述
   * 使用 PowerShell Get-NetAdapter 获取 Name → InterfaceDescription 映射
   * 
   * os.networkInterfaces() 只返回「连接名称」（如 "以太网"、"Wi-Fi"），
   * 但 TUN 适配器的连接名称通常是泛用名（如 "以太网 3"），
   * 真正的关键词（如 "Mihomo"）在 InterfaceDescription 中。
   */
  private getAdapterDescriptions(): Map<string, string> {
    const map = new Map<string, string>();

    try {
      const psOutput = execPowerShell(
        'Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, InterfaceIndex | ConvertTo-Json -Compress'
      );

      if (!psOutput) return map;

      const parsed = safeJsonParse<NetAdapterInfo | NetAdapterInfo[]>(psOutput, []);
      const adapters = Array.isArray(parsed) ? parsed : [parsed];

      for (const adapter of adapters) {
        if (adapter.Name && adapter.InterfaceDescription) {
          map.set(adapter.Name, adapter.InterfaceDescription);
        }
      }
    } catch {
      // Get-NetAdapter 失败时静默回退
    }

    return map;
  }

  /**
   * ★ 核心：适配器分类器（双源匹配）
   * 根据「连接名称」和「接口描述」联合判断是合法工具还是真正的代理风险
   * 
   * @param name        - 连接名称（os.networkInterfaces() 的 key）
   * @param description - 接口描述（Get-NetAdapter 的 InterfaceDescription）
   */
  private classifyAdapter(name: string, description: string = ''): { name: string; cls: AdapterClass; matchedKeyword?: string } {
    const nameLower = name.toLowerCase();
    const descLower = description.toLowerCase();
    // 合并两个来源用于关键词匹配
    const combined = `${nameLower} ${descLower}`;

    // 1. 先检查是否是代理/VPN TUN（最高优先级）
    for (const kw of PROXY_TUN_KEYWORDS) {
      if (combined.includes(kw.toLowerCase())) {
        // ★ 特殊处理：如果匹配到 'wintun'，但同时匹配了安全工具关键词（如 tailscale 也用 wintun），
        // 则以安全工具分类优先
        if (kw === 'wintun' || kw === 'wintun userspace tunnel') {
          const isSafeTool = SAFE_ADAPTER_KEYWORDS.some(sk => combined.includes(sk.toLowerCase()));
          if (isSafeTool) continue; // 跳过，让后续的安全工具检查处理
        }
        return { name, cls: 'proxy_tun', matchedKeyword: kw };
      }
    }

    // 2. 再检查是否是安全合法工具
    for (const kw of SAFE_ADAPTER_KEYWORDS) {
      if (combined.includes(kw.toLowerCase())) {
        return { name, cls: 'safe_tool', matchedKeyword: kw };
      }
    }

    // 3. 检查是否是物理接口（没有匹配任何虚拟关键词）
    const virtualHints = ['virtual', 'veth', 'virbr', 'tun', 'tap', 'bridge', 'miniport'];
    const isVirtual = virtualHints.some(h => combined.includes(h));
    if (!isVirtual) {
      // 进一步检查：Windows 以太网/Wi-Fi 接口名称
      if (nameLower.includes('以太网') || nameLower.includes('ethernet') || nameLower.includes('wi-fi') ||
          nameLower.includes('wlan') || nameLower.includes('无线') || nameLower.includes('lan') ||
          descLower.includes('ethernet') || descLower.includes('wi-fi') || descLower.includes('wireless') ||
          descLower.includes('intel') || descLower.includes('realtek') || descLower.includes('broadcom') ||
          descLower.includes('qualcomm') || descLower.includes('killer') || descLower.includes('mediatek')) {
        return { name, cls: 'physical' };
      }
      // 不含任何虚拟化关键词 → 大概率物理
      return { name, cls: 'physical' };
    }

    // 4. 含虚拟化关键词但不在已知列表 → 未分类
    return { name, cls: 'unknown_virtual' };
  }

  private calculateModuleRisk(items: CheckItem[]): number {
    if (items.length === 0) return 0;
    const riskItems = items.filter(i => i.risk > 0);
    if (riskItems.length === 0) return 0;
    const totalWeightedRisk = riskItems.reduce((sum, item) => sum + item.risk * item.weight, 0);
    const maxPossible = items.length * 10 * CATEGORY_WEIGHTS[this.category];
    return Math.round((totalWeightedRisk / maxPossible) * 100);
  }

  private generateSummary(items: CheckItem[], proxyTunCount: number): string {
    const risks = items.filter(i => i.risk > 3);
    if (risks.length === 0) return '网络环境正常，未发现代理/VPN 风险 ✓';
    if (proxyTunCount > 0) return `★ 检测到 ${proxyTunCount} 个代理 TUN 适配器！建议关闭代理软件的 TUN 模式`;
    return `发现 ${risks.length} 个网络风险项`;
  }
}
