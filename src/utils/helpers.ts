/**
 * AzureScan — 工具函数
 * 跨平台命令执行、哈希、安全解析等
 */

import { execSync, exec } from 'child_process';
import crypto from 'crypto';
import os from 'os';
import { RiskLevel } from '../types';
import { getRiskLevel } from '../config';

// ============================================================
// 跨平台命令执行
// ============================================================

/**
 * 同步执行系统命令，返回 stdout 字符串
 * 失败时返回空字符串而不是抛异常
 */
export function execCommand(command: string, timeout: number = 10000): string {
  try {
    const result = execSync(command, {
      timeout,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    return result.trim();
  } catch {
    return '';
  }
}

/**
 * 异步执行系统命令
 */
export function execCommandAsync(command: string, timeout: number = 15000): Promise<string> {
  return new Promise((resolve) => {
    exec(command, { timeout, encoding: 'utf-8', windowsHide: true }, (error, stdout) => {
      resolve(error ? '' : (stdout || '').trim());
    });
  });
}

/**
 * 执行 PowerShell 命令（Windows 专用）
 */
export function execPowerShell(command: string, timeout: number = 15000): string {
  return execCommand(`powershell -NoProfile -NonInteractive -Command "${command.replace(/"/g, '\\"')}"`, timeout);
}

/**
 * 执行 WMIC 命令（Windows 专用）
 */
export function execWmic(query: string): string {
  return execCommand(`wmic ${query}`, 10000);
}

// ============================================================
// 平台检测
// ============================================================

export const IS_WINDOWS = process.platform === 'win32';
export const IS_MACOS = process.platform === 'darwin';
export const IS_LINUX = process.platform === 'linux';

export function getPlatformName(): string {
  if (IS_WINDOWS) return 'Windows';
  if (IS_MACOS) return 'macOS';
  if (IS_LINUX) return 'Linux';
  return process.platform;
}

// ============================================================
// 哈希 & 加密
// ============================================================

export function sha256(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function md5(data: string): string {
  return crypto.createHash('md5').update(data).digest('hex');
}

export function generateId(): string {
  return crypto.randomUUID();
}

// ============================================================
// 安全解析
// ============================================================

export function safeJsonParse<T>(json: string, fallback: T): T {
  try {
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}

// ============================================================
// 风险评分辅助
// ============================================================

/**
 * 根据单项得分（0-10）返回风险等级
 */
export function itemRiskLevel(risk: number): RiskLevel {
  if (risk <= 2) return RiskLevel.SAFE;
  if (risk <= 5) return RiskLevel.CAUTION;
  if (risk <= 7) return RiskLevel.HIGH;
  return RiskLevel.CRITICAL;
}

/**
 * 创建标准 CheckItem 的快捷方法
 */
export function createCheckItem(
  id: string,
  name: string,
  category: any,
  value: any,
  risk: number,
  weight: number,
  description: string,
  fix?: string,
  platformDetection?: string,
) {
  return {
    id,
    name,
    category,
    value,
    risk: Math.min(10, Math.max(0, risk)),
    weight,
    level: itemRiskLevel(risk),
    description,
    fix,
    platformDetection,
  };
}

// ============================================================
// 字符串工具
// ============================================================

/**
 * MAC 地址标准化为 XX:XX:XX:XX:XX:XX 格式
 */
export function normalizeMac(mac: string): string {
  return mac.replace(/[-]/g, ':').toUpperCase();
}

/**
 * 提取 MAC 前 3 字节（OUI）
 */
export function getOUI(mac: string): string {
  const normalized = normalizeMac(mac);
  return normalized.split(':').slice(0, 3).join(':');
}

/**
 * 格式化字节大小
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

/**
 * 安全获取对象嵌套属性
 */
export function safeGet<T>(fn: () => T, fallback: T): T {
  try {
    return fn() ?? fallback;
  } catch {
    return fallback;
  }
}

// ============================================================
// 定时器工具
// ============================================================

export class Timer {
  private start: number;
  constructor() {
    this.start = Date.now();
  }
  elapsed(): number {
    return Date.now() - this.start;
  }
}
