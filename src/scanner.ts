/**
 * AzureScan — 扫描引擎
 * 协调所有模块运行，汇总结果
 */

import { ModuleResult, ScanReport, ScanProgress } from './types';
import { NetworkModule } from './modules/network';
import { SystemModule } from './modules/system';
import { VirtualizationModule } from './modules/virtualization';
import { BrowserModule } from './modules/browser';
import { IPTransportModule } from './modules/ip-transport';
import { ConsistencyModule } from './modules/consistency';
import { ClaudeSpecificModule } from './modules/claude-specific';
import { RiskScorer } from './utils/risk-scorer';

export type ProgressCallback = (progress: ScanProgress) => void;

export class ScanEngine {
  private scorer = new RiskScorer();

  /**
   * 运行完整扫描
   * @param skipBrowser 是否跳过浏览器指纹（耗时较长）
   * @param onProgress 进度回调
   */
  async runFullScan(skipBrowser: boolean = false, onProgress?: ProgressCallback): Promise<ScanReport> {
    const moduleInstances = [
      new NetworkModule(),
      new SystemModule(),
      new VirtualizationModule(),
      new IPTransportModule(),
      new ClaudeSpecificModule(),
    ];

    if (!skipBrowser) {
      moduleInstances.push(new BrowserModule() as any);
    }

    const totalModules = moduleInstances.length + 1; // +1 for consistency
    const completedModules: string[] = [];
    const results: ModuleResult[] = [];

    // 逐个运行模块
    for (const mod of moduleInstances) {
      if (onProgress) {
        onProgress({
          currentModule: mod.name,
          completedModules: [...completedModules],
          totalModules,
          percentage: Math.round((completedModules.length / totalModules) * 100),
          status: 'running',
        });
      }

      try {
        const result = await mod.run();
        results.push(result);
      } catch (error: any) {
        results.push({
          moduleName: mod.name,
          category: mod.category,
          items: [],
          risk: 0,
          summary: `模块执行失败: ${error.message}`,
          duration: 0,
          success: false,
          error: error.message,
        });
      }

      completedModules.push(mod.name);
    }

    // 最后运行一致性检查模块（依赖其他模块的结果）
    if (onProgress) {
      onProgress({
        currentModule: '一致性交叉检查',
        completedModules: [...completedModules],
        totalModules,
        percentage: Math.round((completedModules.length / totalModules) * 100),
        status: 'running',
      });
    }

    const consistencyModule = new ConsistencyModule();
    consistencyModule.setOtherResults(results);
    
    try {
      const consistencyResult = await consistencyModule.run();
      results.push(consistencyResult);
    } catch (error: any) {
      results.push({
        moduleName: '一致性交叉检查',
        category: consistencyModule.category,
        items: [],
        risk: 0,
        summary: `一致性检查失败: ${error.message}`,
        duration: 0,
        success: false,
        error: error.message,
      });
    }

    completedModules.push('一致性交叉检查');

    // 计算最终报告
    const report = this.scorer.calculateReport(results);

    if (onProgress) {
      onProgress({
        currentModule: '完成',
        completedModules,
        totalModules,
        percentage: 100,
        status: 'completed',
      });
    }

    return report;
  }
}
