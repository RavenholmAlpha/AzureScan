/**
 * AzureScan — 快照管理
 * 保存 / 加载 / 对比 扫描结果快照
 */

import fs from 'fs-extra';
import path from 'path';
import { ScanReport, SnapshotDiff, CheckItem } from '../types';
import { PATHS } from '../config';

export class SnapshotManager {
  private snapshotDir: string;

  constructor() {
    this.snapshotDir = PATHS.fingerprints;
  }

  /**
   * 保存快照
   */
  async save(report: ScanReport): Promise<string> {
    await fs.ensureDir(this.snapshotDir);
    const filename = `snapshot_${report.timestamp.replace(/[:.]/g, '-')}.json`;
    const filepath = path.join(this.snapshotDir, filename);
    await fs.writeJson(filepath, report, { spaces: 2 });
    return filepath;
  }

  /**
   * 获取最新的快照
   */
  async getLatest(): Promise<ScanReport | null> {
    try {
      await fs.ensureDir(this.snapshotDir);
      const files = (await fs.readdir(this.snapshotDir))
        .filter(f => f.startsWith('snapshot_') && f.endsWith('.json'))
        .sort()
        .reverse();

      if (files.length === 0) return null;
      return await fs.readJson(path.join(this.snapshotDir, files[0]));
    } catch {
      return null;
    }
  }

  /**
   * 获取所有快照列表
   */
  async listAll(): Promise<Array<{ filename: string; timestamp: string; totalRisk: number }>> {
    try {
      await fs.ensureDir(this.snapshotDir);
      const files = (await fs.readdir(this.snapshotDir))
        .filter(f => f.startsWith('snapshot_') && f.endsWith('.json'))
        .sort()
        .reverse();

      const results = [];
      for (const file of files) {
        try {
          const data = await fs.readJson(path.join(this.snapshotDir, file));
          results.push({
            filename: file,
            timestamp: data.timestamp,
            totalRisk: data.totalRisk,
          });
        } catch {}
      }
      return results;
    } catch {
      return [];
    }
  }

  /**
   * 对比两个快照
   */
  compare(previous: ScanReport, current: ScanReport): SnapshotDiff {
    const previousIds = new Set(previous.allItems.map(i => i.id));
    const currentIds = new Set(current.allItems.map(i => i.id));

    // 新增的风险项
    const newRisks = current.allItems.filter(
      i => !previousIds.has(i.id) && i.risk > 0
    );

    // 已解决的风险项
    const resolvedRisks = previous.allItems.filter(
      i => !currentIds.has(i.id) && i.risk > 0
    );

    // 风险变化的项
    const changedItems: SnapshotDiff['changedItems'] = [];
    for (const currentItem of current.allItems) {
      const prevItem = previous.allItems.find(i => i.id === currentItem.id);
      if (prevItem && prevItem.risk !== currentItem.risk) {
        changedItems.push({
          id: currentItem.id,
          previousRisk: prevItem.risk,
          currentRisk: currentItem.risk,
          change: currentItem.risk > prevItem.risk ? 'increased' : 'decreased',
        });
      }
    }

    return {
      previous,
      current,
      newRisks,
      resolvedRisks,
      changedItems,
      scoreDelta: current.totalRisk - previous.totalRisk,
    };
  }

  /**
   * 删除所有快照
   */
  async clearAll(): Promise<void> {
    await fs.emptyDir(this.snapshotDir);
  }
}
