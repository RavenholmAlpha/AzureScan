/**
 * AzureScan — Claude Code / 客户端专属检测模块
 * 10+ 检测项
 * 
 * - 解析 ~/.claude/config.json 的 Device ID / Session UUID
 * - WSL / 容器 / SSH 环境检测
 * - Claude Code 遥测风险评估
 */

import fs from 'fs-extra';
import os from 'os';
import path from 'path';
import { CheckCategory, CheckItem, ModuleResult, ScanModule } from '../types';
import { CATEGORY_WEIGHTS, CLAUDE_CONFIG_PATH } from '../config';
import {
  execCommand,
  IS_WINDOWS,
  IS_LINUX,
  createCheckItem,
  Timer,
} from '../utils/helpers';

export class ClaudeSpecificModule implements ScanModule {
  name = 'Claude Code 专属检测';
  category = CheckCategory.CLAUDE_SPECIFIC;

  async run(): Promise<ModuleResult> {
    const timer = new Timer();
    const items: CheckItem[] = [];
    const weight = CATEGORY_WEIGHTS[this.category];

    try {
      // ----------------------------------------------------------
      // 1. Claude 配置文件检测
      // ----------------------------------------------------------
      const claudeConfigExists = await fs.pathExists(CLAUDE_CONFIG_PATH);

      items.push(createCheckItem(
        'claude.config_exists',
        'Claude 配置文件',
        this.category,
        claudeConfigExists ? '存在' : '不存在',
        0,
        weight,
        claudeConfigExists
          ? `Claude 配置文件存在: ${CLAUDE_CONFIG_PATH}`
          : 'Claude 配置文件不存在（可能未安装 Claude Code）',
      ));

      if (claudeConfigExists) {
        try {
          const config = await fs.readJson(CLAUDE_CONFIG_PATH);

          // Device ID
          if (config.deviceId || config.device_id) {
            const deviceId = config.deviceId || config.device_id;
            items.push(createCheckItem(
              'claude.device_id',
              'Claude Device ID',
              this.category,
              `${deviceId.substring(0, 8)}...`,
              0,
              weight,
              `Device ID: ${deviceId.substring(0, 8)}... (已隐藏)`,
              undefined,
              'Device ID 是 Claude 追踪设备的核心标识，更换环境后需注意',
            ));
          }

          // Session UUID
          if (config.sessionUuid || config.session_uuid) {
            items.push(createCheckItem(
              'claude.session_uuid',
              'Claude Session UUID',
              this.category,
              '已设置',
              0,
              weight,
              'Session UUID 已设置',
            ));
          }

          // 检查是否有共享的 User ID（多账户风险）
          if (config.userId || config.user_id) {
            items.push(createCheckItem(
              'claude.user_id',
              'Claude User ID',
              this.category,
              '已关联',
              0,
              weight,
              'Claude User ID 已关联本机',
              undefined,
              '同一 Device ID 关联多个 User ID 会被标记',
            ));
          }
        } catch {
          items.push(createCheckItem(
            'claude.config_parse_error',
            'Claude 配置文件解析',
            this.category,
            '解析失败',
            2,
            weight,
            'Claude 配置文件无法解析',
          ));
        }
      }

      // ----------------------------------------------------------
      // 2. Claude Code 相关目录
      // ----------------------------------------------------------
      const claudeDir = path.join(os.homedir(), '.claude');
      const claudeDirExists = await fs.pathExists(claudeDir);

      if (claudeDirExists) {
        try {
          const files = await fs.readdir(claudeDir);
          items.push(createCheckItem(
            'claude.directory',
            'Claude 目录内容',
            this.category,
            files,
            0,
            weight,
            `Claude 目录包含 ${files.length} 个文件/文件夹`,
          ));

          // 检查是否有多个 session 文件（可能暗示多账户）
          const sessionFiles = files.filter(f => f.includes('session') || f.includes('auth'));
          if (sessionFiles.length > 1) {
            items.push(createCheckItem(
              'claude.multiple_sessions',
              '多个 Session 文件',
              this.category,
              sessionFiles,
              5,
              weight,
              `检测到 ${sessionFiles.length} 个 session/auth 文件，可能存在多账户切换`,
              '清理旧的 session 文件',
              '多账户切换行为可能触发风控',
            ));
          }
        } catch {}
      }

      // ----------------------------------------------------------
      // 3. SSH 环境检测
      // ----------------------------------------------------------
      const sshClient = process.env.SSH_CLIENT;
      const sshConnection = process.env.SSH_CONNECTION;
      const sshTty = process.env.SSH_TTY;
      const isSSH = !!(sshClient || sshConnection || sshTty);

      items.push(createCheckItem(
        'claude.ssh_env',
        'SSH 远程环境',
        this.category,
        isSSH ? '是' : '否',
        isSSH ? 6 : 0,
        weight,
        isSSH ? '⚠️ 当前环境通过 SSH 远程连接' : '非 SSH 环境',
        isSSH ? '在本地物理终端中使用 Claude Code' : undefined,
        'SSH 环境可能暗示使用远程服务器，增加风控评分',
      ));

      // ----------------------------------------------------------
      // 4. WSL 环境检测
      // ----------------------------------------------------------
      if (IS_LINUX) {
        const isWSL = execCommand('cat /proc/version 2>/dev/null').toLowerCase().includes('microsoft');
        if (isWSL) {
          items.push(createCheckItem(
            'claude.wsl',
            'WSL 环境',
            this.category,
            '是',
            5,
            weight,
            '当前环境运行在 WSL 中',
            '在 Windows 原生终端中使用 Claude Code',
            'WSL 环境与 Windows 环境的指纹不一致会增加风险',
          ));
        }
      }

      // ----------------------------------------------------------
      // 5. 容器/Docker 环境
      // ----------------------------------------------------------
      if (IS_LINUX) {
        const dockerEnv = await fs.pathExists('/.dockerenv');
        const cgroupDocker = execCommand('cat /proc/1/cgroup 2>/dev/null').includes('docker');
        const isDocker = dockerEnv || cgroupDocker;

        if (isDocker) {
          items.push(createCheckItem(
            'claude.docker_env',
            'Docker 容器环境',
            this.category,
            '是',
            7,
            weight,
            '⚠️ 当前环境运行在 Docker 容器中',
            '在宿主机上使用 Claude Code',
            '容器环境有明显的指纹特征',
          ));
        }
      }

      // ----------------------------------------------------------
      // 6. 终端类型检测
      // ----------------------------------------------------------
      const term = process.env.TERM;
      const termProgram = process.env.TERM_PROGRAM;
      const shell = process.env.SHELL || process.env.ComSpec;

      items.push(createCheckItem(
        'claude.terminal',
        '终端环境',
        this.category,
        { term, termProgram, shell },
        0,
        weight,
        `终端: ${termProgram || term || 'unknown'}, Shell: ${shell || 'unknown'}`,
        undefined,
        '终端类型是环境指纹的组成部分',
      ));

      // ----------------------------------------------------------
      // 7. Node.js 环境信息（Claude Code 直接使用）
      // ----------------------------------------------------------
      items.push(createCheckItem(
        'claude.node_version',
        'Node.js 版本',
        this.category,
        process.version,
        0,
        weight,
        `Node.js ${process.version} on ${process.platform} ${process.arch}`,
      ));

      // ----------------------------------------------------------
      // 8. 遥测模拟：Claude 会采集什么
      // ----------------------------------------------------------
      const telemetrySimulation = {
        machineId: execCommand(IS_WINDOWS
          ? 'reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid 2>nul'
          : 'cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null'
        ),
        hostname: os.hostname(),
        username: os.userInfo().username,
        homeDir: os.homedir(),
        cpuCount: os.cpus().length,
        totalMem: Math.round(os.totalmem() / (1024 * 1024 * 1024)),
        platform: os.platform(),
        release: os.release(),
        arch: os.arch(),
      };

      items.push(createCheckItem(
        'claude.telemetry_preview',
        'Claude 遥测数据预览',
        this.category,
        telemetrySimulation,
        0,
        weight,
        `Claude 可能采集: hostname(${telemetrySimulation.hostname}), user(${telemetrySimulation.username}), cpu(${telemetrySimulation.cpuCount}核), mem(${telemetrySimulation.totalMem}GB)`,
        undefined,
        '这些数据是 Claude 640+ 遥测事件的基础数据源',
      ));

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
        summary: `Claude 专属检测出错: ${error.message}`,
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
    if (risks.length === 0) return 'Claude 专属检测正常';
    return `发现 ${risks.length} 个 Claude 相关风险项`;
  }
}
