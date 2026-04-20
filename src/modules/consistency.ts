/**
 * AzureScan — 一致性检查模块
 * 最致命，权重 ×3
 * 
 * 交叉校验多模块数据：
 * - IP 地理 vs 系统时区 vs 浏览器时区
 * - 系统语言 vs 浏览器语言 vs IP 国家
 * - 硬件核心数：系统 vs 浏览器
 * - GPU：系统 vs WebGL 渲染器
 * - 内存：系统 vs 浏览器
 */

import { CheckCategory, CheckItem, ModuleResult, ScanModule } from '../types';
import { CATEGORY_WEIGHTS } from '../config';
import { createCheckItem, Timer } from '../utils/helpers';

export class ConsistencyModule implements ScanModule {
  name = '一致性交叉检查';
  category = CheckCategory.CONSISTENCY;

  private otherModuleResults: ModuleResult[] = [];

  /** 注入其它模块的检测结果用于交叉比对 */
  setOtherResults(results: ModuleResult[]) {
    this.otherModuleResults = results;
  }

  async run(): Promise<ModuleResult> {
    const timer = new Timer();
    const items: CheckItem[] = [];
    const weight = CATEGORY_WEIGHTS[this.category];

    try {
      // 从其他模块结果中提取数据
      const allItems = this.otherModuleResults.flatMap(m => m.items);
      
      const findValue = (id: string) => {
        const item = allItems.find(i => i.id === id);
        return item?.value;
      };

      // ----------------------------------------------------------
      // 1. 系统时区 vs 浏览器时区
      // ----------------------------------------------------------
      const sysTimezone = findValue('system.timezone');
      const browserTimezone = findValue('browser.timezone');

      if (sysTimezone && browserTimezone?.timezone) {
        const match = sysTimezone === browserTimezone.timezone;
        items.push(createCheckItem(
          'consistency.timezone',
          '系统时区 vs 浏览器时区',
          this.category,
          { system: sysTimezone, browser: browserTimezone.timezone, match },
          match ? 0 : 9,
          weight,
          match
            ? `时区一致: ${sysTimezone}`
            : `⚠️⚠️ 时区不一致: 系统(${sysTimezone}) ≠ 浏览器(${browserTimezone.timezone})`,
          !match ? '确保系统时区设置正确' : undefined,
          '时区不一致是平台检测的最高优先级信号之一',
        ));
      }

      // ----------------------------------------------------------
      // 2. 系统语言 vs 浏览器语言
      // ----------------------------------------------------------
      const sysLocale = findValue('system.locale');
      const browserLang = findValue('browser.language');

      if (sysLocale && browserLang?.primary) {
        const sysLang = sysLocale.split('-')[0].toLowerCase();
        const brLang = browserLang.primary.split('-')[0].toLowerCase();
        const match = sysLang === brLang;

        items.push(createCheckItem(
          'consistency.language',
          '系统语言 vs 浏览器语言',
          this.category,
          { system: sysLocale, browser: browserLang.primary, match },
          match ? 0 : 7,
          weight,
          match
            ? `语言一致: ${sysLocale}`
            : `⚠️ 语言不一致: 系统(${sysLocale}) ≠ 浏览器(${browserLang.primary})`,
          !match ? '确保浏览器语言与系统语言一致' : undefined,
          '语言不一致暴露环境篡改行为',
        ));
      }

      // ----------------------------------------------------------
      // 3. CPU 核心数：系统 vs 浏览器
      // ----------------------------------------------------------
      const sysCpu = findValue('system.cpu');
      const browserCores = findValue('browser.hardware_concurrency');

      if (sysCpu?.cores && browserCores) {
        const match = sysCpu.cores === browserCores;
        items.push(createCheckItem(
          'consistency.cpu_cores',
          'CPU 核心数一致性',
          this.category,
          { system: sysCpu.cores, browser: browserCores, match },
          match ? 0 : 7,
          weight,
          match
            ? `CPU 核心数一致: ${sysCpu.cores}`
            : `⚠️ CPU 核心数不一致: 系统(${sysCpu.cores}) ≠ 浏览器(${browserCores})`,
          !match ? '检查浏览器 hardwareConcurrency 欺骗设置' : undefined,
          '核心数不一致暴露指纹篡改',
        ));
      }

      // ----------------------------------------------------------
      // 4. 内存：系统 vs 浏览器
      // ----------------------------------------------------------
      const sysMem = findValue('system.memory');
      const browserMem = findValue('browser.device_memory');

      if (sysMem?.total && browserMem && browserMem !== 'N/A') {
        // deviceMemory 返回的是近似值（0.25, 0.5, 1, 2, 4, 8）
        const sysGB = sysMem.total;
        const brGB = browserMem;
        // Chrome 的 deviceMemory 会被截断到最近的 2^n
        const expectedBrowserMem = Math.pow(2, Math.floor(Math.log2(sysGB)));
        const match = brGB >= expectedBrowserMem / 2; // 允许误差

        items.push(createCheckItem(
          'consistency.memory',
          '内存一致性',
          this.category,
          { system: `${sysGB}GB`, browser: `${brGB}GB`, match },
          match ? 0 : 5,
          weight,
          match
            ? `内存一致: 系统 ${sysGB}GB / 浏览器 ${brGB}GB`
            : `⚠️ 内存不一致: 系统 ${sysGB}GB / 浏览器 ${brGB}GB`,
          !match ? '检查浏览器指纹欺骗设置' : undefined,
        ));
      }

      // ----------------------------------------------------------
      // 5. 屏幕分辨率：系统 vs 浏览器
      // ----------------------------------------------------------
      const vmScreenRes = findValue('vm.screen_resolution');
      const browserScreen = findValue('browser.screen');

      if (vmScreenRes && browserScreen) {
        const sysRes = vmScreenRes;
        const brRes = `${browserScreen.width}x${browserScreen.height}`;
        const match = sysRes === brRes;

        items.push(createCheckItem(
          'consistency.screen',
          '屏幕分辨率一致性',
          this.category,
          { system: sysRes, browser: brRes, match },
          match ? 0 : 6,
          weight,
          match
            ? `分辨率一致: ${sysRes}`
            : `⚠️ 分辨率不一致: 系统(${sysRes}) ≠ 浏览器(${brRes})`,
          !match ? '确保虚拟机分辨率与浏览器报告一致' : undefined,
        ));
      }

      // ----------------------------------------------------------
      // 6. IP 时区 vs 所有时区源
      // ----------------------------------------------------------
      const ipTimezoneConsistency = findValue('ip.timezone_consistency');
      if (ipTimezoneConsistency && !ipTimezoneConsistency.match) {
        items.push(createCheckItem(
          'consistency.ip_timezone',
          'IP 时区 vs 系统时区（重复确认）',
          this.category,
          ipTimezoneConsistency,
          8,
          weight,
          `⚠️⚠️ IP 时区(${ipTimezoneConsistency.ipTimezone}) 与系统时区(${ipTimezoneConsistency.systemTimezone}) 不一致`,
          '使用与 IP 所在地区相同的系统时区，或更换为本地 IP',
          '这是一致性检查中权重最高的项，×3 乘数',
        ));
      }

      // ----------------------------------------------------------
      // 7. ★ 代理 TUN + VM 检测联合评估
      // ----------------------------------------------------------
      const proxyTunAdapters = findValue('network.proxy_tun_count');
      const vmProcesses = findValue('vm.processes');
      const vmRegistry = findValue('vm.registry_keys');

      let vmSignatureCount = 0;
      // 只有代理 TUN 适配器才计入（合法工具不算）
      if (proxyTunAdapters && Array.isArray(proxyTunAdapters) && proxyTunAdapters.length > 0) vmSignatureCount++;
      if (vmProcesses && Array.isArray(vmProcesses) && vmProcesses.length > 0) vmSignatureCount++;
      if (vmRegistry && Array.isArray(vmRegistry) && vmRegistry.length > 0) vmSignatureCount++;

      if (vmSignatureCount >= 2) {
        items.push(createCheckItem(
          'consistency.vm_multi_signal',
          '多重虚拟化信号',
          this.category,
          `${vmSignatureCount} 个独立来源`,
          9,
          weight,
          `⚠️⚠️ 从 ${vmSignatureCount} 个独立来源检测到虚拟化信号（代理TUN+进程+注册表）`,
          '彻底清理虚拟化环境或使用物理机',
          '多重虚拟化信号交叉确认 = 几乎确定的虚拟环境',
        ));
      }

      // ----------------------------------------------------------
      // 8. ★ 代理多重信号联合评估
      // ----------------------------------------------------------
      const proxyEnv = findValue('network.proxy_env');
      const systemProxy = findValue('network.system_proxy');
      const ipProxy = findValue('ip.proxy');
      const proxyProcesses = findValue('network.proxy_processes');

      let proxySignals = 0;
      if (proxyEnv && typeof proxyEnv === 'object') proxySignals++;
      if (systemProxy && systemProxy !== '未启用') proxySignals++;
      if (ipProxy === true) proxySignals++;
      // ★ 使用新的代理进程检测结果
      if (proxyProcesses && Array.isArray(proxyProcesses) && proxyProcesses.length > 0) proxySignals++;
      // ★ 代理 TUN 适配器也是代理信号
      if (proxyTunAdapters && Array.isArray(proxyTunAdapters) && proxyTunAdapters.length > 0) proxySignals++;

      if (proxySignals >= 2) {
        items.push(createCheckItem(
          'consistency.proxy_multi_signal',
          '多重代理/VPN 信号',
          this.category,
          `${proxySignals} 个代理信号`,
          8,
          weight,
          `⚠️ 检测到 ${proxySignals} 个代理/VPN 信号源`,
          '关闭所有代理/VPN 后重新检测',
          '多个代理信号同时存在大幅提升风控评分',
        ));
      }

      // ----------------------------------------------------------
      // 如果没有足够的跨模块数据，添加提示
      // ----------------------------------------------------------
      if (items.length === 0) {
        items.push(createCheckItem(
          'consistency.no_data',
          '一致性检查数据不足',
          this.category,
          '需要更多模块数据',
          0,
          weight,
          '其他模块数据不足，一致性检查无法完成。请运行完整扫描（--full）。',
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
        summary: this.generateSummary(items),
        duration: timer.elapsed(),
        success: true,
      };
    } catch (error: any) {
      return {
        moduleName: this.name,
        category: this.category,
        items,
        risk: 0,
        summary: `一致性检查出错: ${error.message}`,
        duration: timer.elapsed(),
        success: false,
        error: error.message,
      };
    }
  }

  private calculateModuleRisk(items: CheckItem[]): number {
    if (items.length === 0) return 0;
    const totalWeightedRisk = items.reduce((sum, item) => sum + item.risk * item.weight, 0);
    const maxPossible = items.length * 10 * CATEGORY_WEIGHTS[this.category];
    return Math.round((totalWeightedRisk / maxPossible) * 100);
  }

  private generateSummary(items: CheckItem[]): string {
    const risks = items.filter(i => i.risk > 3);
    if (risks.length === 0) return '一致性检查通过，各指标一致';
    return `⚠️ 发现 ${risks.length} 个一致性问题（×3 权重），严重影响评分`;
  }
}
