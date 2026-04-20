/**
 * AzureScan — 核心类型定义
 * 所有检测模块的标准接口
 */

// ============================================================
// 风险等级枚举
// ============================================================
export enum RiskLevel {
  SAFE = 'safe',           // 0-25: 极安全（绿）
  CAUTION = 'caution',     // 26-50: 建议优化（黄）
  HIGH = 'high',           // 51-75: 高风险（橙）
  CRITICAL = 'critical',   // 76+: 几乎必封（红）
}

// ============================================================
// 单项检测结果
// ============================================================
export interface CheckItem {
  /** 唯一标识，如 'network.virtual_adapter.vmware' */
  id: string;
  /** 检测项名称 */
  name: string;
  /** 所属大类 */
  category: CheckCategory;
  /** 检测到的实际值 */
  value: any;
  /** 该项风险评分 0-10 */
  risk: number;
  /** 权重（由 config 定义） */
  weight: number;
  /** 风险等级 */
  level: RiskLevel;
  /** 检测说明 */
  description: string;
  /** 修复建议 */
  fix?: string;
  /** 平台可能的判断方式 */
  platformDetection?: string;
}

// ============================================================
// 检测类别
// ============================================================
export enum CheckCategory {
  NETWORK = 'network',
  IP_TRANSPORT = 'ip_transport',
  BROWSER = 'browser',
  SYSTEM = 'system',
  VIRTUALIZATION = 'virtualization',
  CONSISTENCY = 'consistency',
  CLAUDE_SPECIFIC = 'claude_specific',
  BEHAVIORAL = 'behavioral',
  ADVANCED = 'advanced',
}

// ============================================================
// 模块检测结果（每个模块返回）
// ============================================================
export interface ModuleResult {
  /** 模块名称 */
  moduleName: string;
  /** 所属类别 */
  category: CheckCategory;
  /** 所有检测项 */
  items: CheckItem[];
  /** 模块整体风险 0-100 */
  risk: number;
  /** 模块摘要 */
  summary: string;
  /** 检测耗时（ms） */
  duration: number;
  /** 是否成功完成 */
  success: boolean;
  /** 错误信息（如果有） */
  error?: string;
}

// ============================================================
// 完整扫描报告
// ============================================================
export interface ScanReport {
  /** 报告 ID */
  id: string;
  /** 扫描时间 */
  timestamp: string;
  /** AzureScan 版本 */
  version: string;
  /** 总风险评分 0-100 */
  totalRisk: number;
  /** 总风险等级 */
  riskLevel: RiskLevel;
  /** 各模块结果 */
  modules: ModuleResult[];
  /** 所有检测项（扁平化） */
  allItems: CheckItem[];
  /** 分类统计 */
  stats: ReportStats;
  /** 系统信息摘要 */
  systemSummary: SystemSummary;
  /** 扫描总耗时（ms） */
  totalDuration: number;
}

// ============================================================
// 报告统计
// ============================================================
export interface ReportStats {
  totalChecks: number;
  safeCount: number;
  cautionCount: number;
  highCount: number;
  criticalCount: number;
  /** 按类别分组的风险得分 */
  categoryScores: Record<CheckCategory, number>;
}

// ============================================================
// 系统信息摘要
// ============================================================
export interface SystemSummary {
  os: string;
  hostname: string;
  cpu: string;
  gpu: string;
  ram: string;
  ip: string;
  timezone: string;
  locale: string;
}

// ============================================================
// 快照对比
// ============================================================
export interface SnapshotDiff {
  /** 前一次快照 */
  previous: ScanReport;
  /** 当前快照 */
  current: ScanReport;
  /** 新增的风险项 */
  newRisks: CheckItem[];
  /** 已解决的风险项 */
  resolvedRisks: CheckItem[];
  /** 风险变化的项 */
  changedItems: Array<{
    id: string;
    previousRisk: number;
    currentRisk: number;
    change: 'increased' | 'decreased';
  }>;
  /** 总分变化 */
  scoreDelta: number;
}

// ============================================================
// 模块接口（每个检测模块实现）
// ============================================================
export interface ScanModule {
  name: string;
  category: CheckCategory;
  run(): Promise<ModuleResult>;
}

// ============================================================
// CLI 选项
// ============================================================
export interface CLIOptions {
  full: boolean;
  html: boolean;
  json: boolean;
  md: boolean;
  saveSnapshot: boolean;
  compare: boolean;
  output: string;
  gui: boolean;
}

// ============================================================
// Web GUI API 响应
// ============================================================
export interface APIResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: string;
}

// ============================================================
// 扫描进度（供 GUI 实时推送）
// ============================================================
export interface ScanProgress {
  currentModule: string;
  completedModules: string[];
  totalModules: number;
  percentage: number;
  status: 'running' | 'completed' | 'error';
}
