/**
 * AzureScan — 报告生成器
 * HTML / Markdown / JSON 三种格式
 */

import fs from 'fs-extra';
import path from 'path';
import { ScanReport, CheckItem, RiskLevel, SnapshotDiff, CheckCategory } from '../types';
import { PATHS, getRiskColor, getRiskLabel, getRiskLevel } from '../config';

export class ReportGenerator {
  /**
   * 生成所有格式的报告
   */
  async generateAll(report: ScanReport, outputDir?: string): Promise<{ html: string; md: string; json: string }> {
    const dir = outputDir || PATHS.reports;
    await fs.ensureDir(dir);

    const timestamp = report.timestamp.replace(/[:.]/g, '-');
    const htmlPath = path.join(dir, `report_${timestamp}.html`);
    const mdPath = path.join(dir, `report_${timestamp}.md`);
    const jsonPath = path.join(dir, `report_${timestamp}.json`);

    await Promise.all([
      fs.writeFile(htmlPath, this.generateHTML(report), 'utf-8'),
      fs.writeFile(mdPath, this.generateMarkdown(report), 'utf-8'),
      fs.writeJson(jsonPath, report, { spaces: 2 }),
    ]);

    return { html: htmlPath, md: mdPath, json: jsonPath };
  }

  /**
   * 生成 HTML 报告
   */
  generateHTML(report: ScanReport): string {
    const riskColor = getRiskColor(report.riskLevel);
    const riskLabel = getRiskLabel(report.riskLevel);

    // 分类统计
    const categoryNames: Record<string, string> = {
      [CheckCategory.NETWORK]: '网络接口',
      [CheckCategory.IP_TRANSPORT]: 'IP & 传输层',
      [CheckCategory.BROWSER]: '浏览器指纹',
      [CheckCategory.SYSTEM]: '系统硬件',
      [CheckCategory.VIRTUALIZATION]: '虚拟化检测',
      [CheckCategory.CONSISTENCY]: '一致性检查',
      [CheckCategory.CLAUDE_SPECIFIC]: 'Claude 专属',
      [CheckCategory.BEHAVIORAL]: '行为分析',
      [CheckCategory.ADVANCED]: '高阶预判',
    };

    const moduleCards = report.modules.map(m => {
      const moduleRiskColor = getRiskColor(getRiskLevel(m.risk));
      const itemRows = m.items.map(item => {
        const itemColor = getRiskColor(item.level);
        const valueStr = typeof item.value === 'object' ? JSON.stringify(item.value, null, 1) : String(item.value);
        const isInfo = item.risk === 0 && (item.name.includes('ℹ️') || item.name.includes('✓') || item.description.includes('不计分') || item.description.includes('合法'));
        const rowClass = isInfo ? 'item-row info-row' : 'item-row';
        const riskDisplay = isInfo
          ? `<span class="info-badge">ℹ️ 信息</span>`
          : `<span class="risk-badge" style="color:${itemColor};background:${itemColor}15">${item.risk}/10</span>`;
        return `
          <tr class="${rowClass}" data-risk="${item.risk}">
            <td><span class="risk-dot" style="background:${isInfo ? 'var(--info)' : itemColor}"></span>${this.escapeHtml(item.name)}</td>
            <td class="value-cell"><code>${this.escapeHtml(valueStr.substring(0, 120))}</code></td>
            <td>${riskDisplay}</td>
            <td>${this.escapeHtml(item.description)}</td>
            <td class="fix-cell">${item.fix ? this.escapeHtml(item.fix) : '<span class="no-fix">—</span>'}</td>
          </tr>`;
      }).join('');

      return `
        <div class="module-card">
          <div class="module-header" onclick="this.parentElement.classList.toggle('collapsed')">
            <div class="module-title">
              <span class="module-icon">${this.getCategoryIcon(m.category)}</span>
              <h3>${this.escapeHtml(m.moduleName)}</h3>
              <span class="module-count">${m.items.length} 项</span>
            </div>
            <div class="module-meta">
              <span class="module-risk" style="background:${moduleRiskColor}">${m.risk}%</span>
              <span class="module-time">${m.duration}ms</span>
              <span class="toggle-icon">▼</span>
            </div>
          </div>
          <div class="module-body">
            <p class="module-summary">${this.escapeHtml(m.summary)}</p>
            <table class="items-table">
              <thead>
                <tr>
                  <th>检测项</th>
                  <th>检测值</th>
                  <th>风险</th>
                  <th>说明</th>
                  <th>修复建议</th>
                </tr>
              </thead>
              <tbody>${itemRows}</tbody>
            </table>
          </div>
        </div>`;
    }).join('');

    // 分类雷达图数据
    const categoryLabels = Object.entries(report.stats.categoryScores)
      .filter(([cat]) => report.modules.some(m => m.category === cat))
      .map(([cat]) => categoryNames[cat] || cat);
    const categoryValues = Object.entries(report.stats.categoryScores)
      .filter(([cat]) => report.modules.some(m => m.category === cat))
      .map(([, val]) => val);

    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AzureScan 环境安全报告</title>
  <style>
    :root {
      --bg: #0a0a0f;
      --card: #12121a;
      --card-hover: #1a1a25;
      --border: #2a2a3a;
      --text: #e0e0e8;
      --text-dim: #8888a0;
      --accent: #6366f1;
      --accent-glow: rgba(99,102,241,0.15);
      --green: #22c55e;
      --yellow: #eab308;
      --orange: #f97316;
      --red: #ef4444;
      --info: #38bdf8;
      --info-bg: rgba(56,189,248,0.06);
    }
    * { margin:0; padding:0; box-sizing:border-box; }
    body {
      font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      min-height: 100vh;
    }
    .container { max-width: 1400px; margin: 0 auto; padding: 24px; }
    
    /* Header */
    .header {
      text-align: center;
      padding: 48px 0 32px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 32px;
    }
    .header h1 {
      font-size: 2.5rem;
      font-weight: 800;
      background: linear-gradient(135deg, #6366f1, #a78bfa, #c084fc);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 8px;
    }
    .header .subtitle { color: var(--text-dim); font-size: 0.95rem; }
    .header .timestamp { color: var(--text-dim); font-size: 0.8rem; margin-top: 4px; }
    
    /* Score Ring */
    .score-section {
      display: flex;
      justify-content: center;
      align-items: center;
      gap: 48px;
      margin: 40px 0;
      flex-wrap: wrap;
    }
    .score-ring {
      position: relative;
      width: 200px;
      height: 200px;
    }
    .score-ring svg { transform: rotate(-90deg); }
    .score-ring circle {
      fill: none;
      stroke-width: 12;
      stroke-linecap: round;
    }
    .score-ring .bg-circle { stroke: var(--border); }
    .score-ring .fg-circle {
      stroke: ${riskColor};
      stroke-dasharray: 565;
      stroke-dashoffset: ${565 - (565 * report.totalRisk / 100)};
      transition: stroke-dashoffset 1.5s ease-out;
      filter: drop-shadow(0 0 8px ${riskColor}66);
    }
    .score-value {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      text-align: center;
    }
    .score-value .number {
      font-size: 3rem;
      font-weight: 800;
      color: ${riskColor};
      line-height: 1;
    }
    .score-value .label {
      font-size: 0.85rem;
      color: var(--text-dim);
      margin-top: 4px;
    }
    .score-value .level {
      font-size: 1.1rem;
      font-weight: 700;
      color: ${riskColor};
      margin-top: 2px;
    }
    
    /* Summary Cards */
    .summary-cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 16px;
      max-width: 700px;
    }
    .summary-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
      text-align: center;
    }
    .summary-card .count {
      font-size: 2rem;
      font-weight: 700;
      line-height: 1;
    }
    .summary-card .desc {
      font-size: 0.75rem;
      color: var(--text-dim);
      margin-top: 4px;
    }
    
    /* System Info */
    .sys-info {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px 24px;
      margin: 24px 0;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
    }
    .sys-info-item { display: flex; gap: 8px; font-size: 0.85rem; }
    .sys-info-item .label { color: var(--text-dim); }
    .sys-info-item .value { color: var(--text); font-weight: 500; }
    
    /* Module Cards */
    .module-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      margin-bottom: 16px;
      overflow: hidden;
      transition: border-color 0.2s;
    }
    .module-card:hover { border-color: var(--accent); }
    .module-card.collapsed .module-body { display: none; }
    .module-card.collapsed .toggle-icon { transform: rotate(-90deg); }
    .module-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 16px 20px;
      cursor: pointer;
      user-select: none;
    }
    .module-header:hover { background: var(--card-hover); }
    .module-title { display: flex; align-items: center; gap: 10px; }
    .module-icon { font-size: 1.3rem; }
    .module-title h3 { font-size: 1rem; font-weight: 600; }
    .module-count {
      background: var(--accent-glow);
      color: var(--accent);
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .module-meta { display: flex; align-items: center; gap: 12px; }
    .module-risk {
      padding: 3px 10px;
      border-radius: 8px;
      font-size: 0.8rem;
      font-weight: 700;
      color: #fff;
    }
    .module-time { color: var(--text-dim); font-size: 0.75rem; }
    .toggle-icon { color: var(--text-dim); transition: transform 0.2s; font-size: 0.8rem; }
    
    .module-body { padding: 0 20px 20px; }
    .module-summary { color: var(--text-dim); font-size: 0.85rem; margin-bottom: 12px; }
    
    /* Items Table */
    .items-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
    }
    .items-table th {
      text-align: left;
      padding: 8px 10px;
      color: var(--text-dim);
      font-weight: 600;
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
    }
    .items-table td {
      padding: 8px 10px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    .items-table tr:last-child td { border-bottom: none; }
    .item-row:hover { background: var(--card-hover); }
    .risk-dot {
      display: inline-block;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      margin-right: 6px;
      vertical-align: middle;
    }
    .value-cell code {
      background: rgba(99,102,241,0.1);
      padding: 1px 5px;
      border-radius: 4px;
      font-size: 0.78rem;
      word-break: break-all;
    }
    .fix-cell { color: var(--accent); font-size: 0.78rem; }
    .no-fix { color: var(--text-dim); }
    .item-row.info-row { background: var(--info-bg); }
    .item-row.info-row:hover { background: rgba(56,189,248,0.12); }
    .info-badge {
      display: inline-block;
      background: rgba(56,189,248,0.15);
      color: var(--info);
      padding: 1px 6px;
      border-radius: 4px;
      font-size: 0.72rem;
      font-weight: 600;
    }
    .risk-badge {
      display: inline-block;
      padding: 1px 6px;
      border-radius: 4px;
      font-size: 0.72rem;
      font-weight: 700;
    }
    
    /* Footer */
    .footer {
      text-align: center;
      padding: 32px 0;
      color: var(--text-dim);
      font-size: 0.8rem;
      border-top: 1px solid var(--border);
      margin-top: 32px;
    }
    
    /* Responsive */
    @media (max-width: 768px) {
      .container { padding: 16px; }
      .header h1 { font-size: 1.8rem; }
      .score-section { gap: 24px; }
      .items-table { font-size: 0.75rem; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🛡️ AzureScan</h1>
      <div class="subtitle">AI平台环境指纹自检报告 v${report.version}</div>
      <div class="timestamp">${new Date(report.timestamp).toLocaleString('zh-CN')} | 总耗时 ${report.totalDuration}ms | ${report.allItems.length} 项检测</div>
    </div>

    <div class="score-section">
      <div class="score-ring">
        <svg width="200" height="200" viewBox="0 0 200 200">
          <circle class="bg-circle" cx="100" cy="100" r="90"/>
          <circle class="fg-circle" cx="100" cy="100" r="90"/>
        </svg>
        <div class="score-value">
          <div class="number">${report.totalRisk}</div>
          <div class="label">风险评分</div>
          <div class="level">${riskLabel}</div>
        </div>
      </div>
      <div class="summary-cards">
        <div class="summary-card">
          <div class="count" style="color:var(--green)">${report.stats.safeCount}</div>
          <div class="desc">安全项</div>
        </div>
        <div class="summary-card">
          <div class="count" style="color:var(--yellow)">${report.stats.cautionCount}</div>
          <div class="desc">注意项</div>
        </div>
        <div class="summary-card">
          <div class="count" style="color:var(--orange)">${report.stats.highCount}</div>
          <div class="desc">高风险</div>
        </div>
        <div class="summary-card">
          <div class="count" style="color:var(--red)">${report.stats.criticalCount}</div>
          <div class="desc">严重风险</div>
        </div>
      </div>
    </div>

    <div class="sys-info">
      <div class="sys-info-item"><span class="label">操作系统:</span><span class="value">${this.escapeHtml(report.systemSummary.os)}</span></div>
      <div class="sys-info-item"><span class="label">主机名:</span><span class="value">${this.escapeHtml(report.systemSummary.hostname)}</span></div>
      <div class="sys-info-item"><span class="label">CPU:</span><span class="value">${this.escapeHtml(report.systemSummary.cpu)}</span></div>
      <div class="sys-info-item"><span class="label">GPU:</span><span class="value">${this.escapeHtml(report.systemSummary.gpu)}</span></div>
      <div class="sys-info-item"><span class="label">内存:</span><span class="value">${this.escapeHtml(report.systemSummary.ram)}</span></div>
      <div class="sys-info-item"><span class="label">IP:</span><span class="value">${this.escapeHtml(report.systemSummary.ip)}</span></div>
      <div class="sys-info-item"><span class="label">时区:</span><span class="value">${this.escapeHtml(report.systemSummary.timezone)}</span></div>
      <div class="sys-info-item"><span class="label">语言:</span><span class="value">${this.escapeHtml(report.systemSummary.locale)}</span></div>
    </div>

    <h2 style="font-size:1.3rem;margin:32px 0 16px;font-weight:700;">📋 检测详情</h2>
    ${moduleCards}

    <div class="footer">
      AzureScan v${report.version} — 纯本地运行，无数据上传 — ${new Date().getFullYear()}
    </div>
  </div>

  <script>
    // 默认折叠无风险的模块
    document.querySelectorAll('.module-card').forEach(card => {
      const riskEl = card.querySelector('.module-risk');
      if (riskEl && riskEl.textContent.trim() === '0%') {
        card.classList.add('collapsed');
      }
    });
  </script>
</body>
</html>`;
  }

  /**
   * 生成 Markdown 报告
   */
  generateMarkdown(report: ScanReport): string {
    const riskLabel = getRiskLabel(report.riskLevel);
    let md = `# 🛡️ AzureScan 环境安全报告\n\n`;
    md += `> 扫描时间: ${report.timestamp} | 版本: v${report.version} | 耗时: ${report.totalDuration}ms\n\n`;
    md += `## 总体风险评分: **${report.totalRisk}/100** (${riskLabel})\n\n`;
    md += `| 指标 | 数量 |\n|------|------|\n`;
    md += `| ✅ 安全项 | ${report.stats.safeCount} |\n`;
    md += `| ⚠️ 注意项 | ${report.stats.cautionCount} |\n`;
    md += `| 🔶 高风险 | ${report.stats.highCount} |\n`;
    md += `| 🔴 严重风险 | ${report.stats.criticalCount} |\n`;
    md += `| 📊 总检测项 | ${report.stats.totalChecks} |\n\n`;

    md += `## 系统信息\n\n`;
    md += `- **OS**: ${report.systemSummary.os}\n`;
    md += `- **CPU**: ${report.systemSummary.cpu}\n`;
    md += `- **GPU**: ${report.systemSummary.gpu}\n`;
    md += `- **RAM**: ${report.systemSummary.ram}\n`;
    md += `- **IP**: ${report.systemSummary.ip}\n`;
    md += `- **时区**: ${report.systemSummary.timezone}\n\n`;

    md += `---\n\n`;

    for (const module of report.modules) {
      md += `## ${module.moduleName} (${module.risk}%)\n\n`;
      md += `> ${module.summary}\n\n`;

      const riskItems = module.items.filter(i => i.risk > 0);
      const safeItems = module.items.filter(i => i.risk === 0);

      if (riskItems.length > 0) {
        md += `### ⚠️ 风险项\n\n`;
        md += `| 检测项 | 风险 | 说明 | 修复建议 |\n|--------|------|------|----------|\n`;
        for (const item of riskItems) {
          md += `| ${item.name} | ${item.risk}/10 | ${item.description.substring(0, 60)} | ${item.fix || '—'} |\n`;
        }
        md += '\n';
      }

      // ★ 区分信息项和安全项
      const infoItems = safeItems.filter(i => i.name.includes('ℹ️') || i.description.includes('不计分') || i.description.includes('合法'));
      const normalSafe = safeItems.filter(i => !infoItems.includes(i));

      if (infoItems.length > 0) {
        md += `### ℹ️ 信息项（不影响评分，${infoItems.length} 项）\n\n`;
        for (const item of infoItems) {
          md += `- 💠 **${item.name}**: ${item.description.substring(0, 80)}\n`;
        }
        md += '\n';
      }

      if (normalSafe.length > 0) {
        md += `### ✅ 安全项 (${normalSafe.length} 项通过)\n\n`;
        for (const item of normalSafe) {
          md += `- **${item.name}**: ${item.description.substring(0, 80)}\n`;
        }
        md += '\n';
      }

      md += `---\n\n`;
    }

    md += `\n*AzureScan v${report.version} — 纯本地运行，无数据上传*\n`;
    return md;
  }

  /**
   * 获取类别图标
   */
  private getCategoryIcon(category: CheckCategory): string {
    const icons: Record<string, string> = {
      [CheckCategory.NETWORK]: '🌐',
      [CheckCategory.IP_TRANSPORT]: '📡',
      [CheckCategory.BROWSER]: '🔍',
      [CheckCategory.SYSTEM]: '💻',
      [CheckCategory.VIRTUALIZATION]: '🖥️',
      [CheckCategory.CONSISTENCY]: '🔗',
      [CheckCategory.CLAUDE_SPECIFIC]: '🤖',
      [CheckCategory.BEHAVIORAL]: '👁️',
      [CheckCategory.ADVANCED]: '🚀',
    };
    return icons[category] || '📋';
  }

  /**
   * HTML 转义
   */
  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}
