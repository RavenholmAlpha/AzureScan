/**
 * AzureScan — 风险评分引擎
 * 150 项加权评分，总分 0-100
 */

import { CheckItem, CheckCategory, ModuleResult, ScanReport, ReportStats, RiskLevel, SystemSummary } from '../types';
import { CATEGORY_WEIGHTS, getRiskLevel, VERSION } from '../config';
import { generateId } from '../utils/helpers';

export class RiskScorer {
  /**
   * 根据所有模块结果计算完整报告
   */
  calculateReport(moduleResults: ModuleResult[]): ScanReport {
    const allItems = moduleResults.flatMap(m => m.items);
    const totalRisk = this.calculateTotalRisk(allItems);
    const riskLevel = getRiskLevel(totalRisk);
    const stats = this.calculateStats(allItems);
    const systemSummary = this.extractSystemSummary(allItems);
    const totalDuration = moduleResults.reduce((sum, m) => sum + m.duration, 0);

    return {
      id: generateId(),
      timestamp: new Date().toISOString(),
      version: VERSION,
      totalRisk,
      riskLevel,
      modules: moduleResults,
      allItems,
      stats,
      systemSummary,
      totalDuration,
    };
  }

  /**
   * 计算总体风险评分 0-100
   * 
   * 算法：
   * 1. 每项 risk(0-10) × weight(由类别决定)
   * 2. 加权求和 / 理论最大值 × 100
   * 3. 但使用 softmax 风格的非线性映射避免极端值
   */
  private calculateTotalRisk(items: CheckItem[]): number {
    if (items.length === 0) return 0;

    // 加权风险总和
    const totalWeightedRisk = items.reduce((sum, item) => {
      return sum + item.risk * item.weight;
    }, 0);

    // 理论最大值
    const maxPossible = items.reduce((sum, item) => {
      return sum + 10 * item.weight;
    }, 0);

    if (maxPossible === 0) return 0;

    // 线性比例
    const linearScore = (totalWeightedRisk / maxPossible) * 100;

    // 非线性调整：放大中间区域的区分度
    // 使用 sigmoid-like 映射
    const adjusted = 100 * (1 - Math.exp(-linearScore * 3 / 100));

    return Math.round(Math.min(100, Math.max(0, adjusted)));
  }

  /**
   * 计算统计数据
   */
  private calculateStats(items: CheckItem[]): ReportStats {
    const stats: ReportStats = {
      totalChecks: items.length,
      safeCount: items.filter(i => i.level === RiskLevel.SAFE).length,
      cautionCount: items.filter(i => i.level === RiskLevel.CAUTION).length,
      highCount: items.filter(i => i.level === RiskLevel.HIGH).length,
      criticalCount: items.filter(i => i.level === RiskLevel.CRITICAL).length,
      categoryScores: {} as Record<CheckCategory, number>,
    };

    // 按类别计算分数
    for (const category of Object.values(CheckCategory)) {
      const categoryItems = items.filter(i => i.category === category);
      if (categoryItems.length === 0) {
        stats.categoryScores[category] = 0;
        continue;
      }
      const catWeightedRisk = categoryItems.reduce((s, i) => s + i.risk * i.weight, 0);
      const catMaxPossible = categoryItems.length * 10 * (CATEGORY_WEIGHTS[category] || 1);
      stats.categoryScores[category] = Math.round((catWeightedRisk / catMaxPossible) * 100);
    }

    return stats;
  }

  /**
   * 从检测结果中提取系统摘要
   */
  private extractSystemSummary(items: CheckItem[]): SystemSummary {
    const findValue = (id: string) => {
      const item = items.find(i => i.id === id);
      return item?.value;
    };

    const osInfo = findValue('system.os_info');
    const cpuInfo = findValue('system.cpu');
    const memInfo = findValue('system.memory');
    const ipInfo = findValue('ip.public_ip');
    const tzInfo = findValue('system.timezone');
    const localeInfo = findValue('system.locale');

    // GPU: 从系统模块中找
    const gpuItem = items.find(i => i.id.startsWith('system.gpu.'));
    
    return {
      os: osInfo ? `${osInfo.distro} ${osInfo.release}` : process.platform,
      hostname: require('os').hostname(),
      cpu: cpuInfo ? `${cpuInfo.manufacturer} ${cpuInfo.brand}` : 'Unknown',
      gpu: gpuItem ? gpuItem.value?.model || 'Unknown' : 'Unknown',
      ram: memInfo ? `${memInfo.total} GB` : 'Unknown',
      ip: ipInfo || 'Unknown',
      timezone: tzInfo || Intl.DateTimeFormat().resolvedOptions().timeZone,
      locale: localeInfo || Intl.DateTimeFormat().resolvedOptions().locale,
    };
  }
}
