/**
 * AzureScan — CLI 入口
 * 一键运行所有检测模块，生成报告
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import path from 'path';
import { ScanEngine } from './scanner';
import { ReportGenerator } from './utils/report-generator';
import { SnapshotManager } from './utils/snapshot';
import { VERSION, APP_NAME, getRiskColor, getRiskLabel } from './config';
import { RiskLevel } from './types';

const program = new Command();

program
  .name('azurescan')
  .description('AI平台环境指纹自检工具 — 本地环境风控自查')
  .version(VERSION)
  .option('--full', '完整扫描（包含浏览器指纹，需要 Playwright）', false)
  .option('--html', '生成 HTML 报告', false)
  .option('--json', '生成 JSON 报告', false)
  .option('--md', '生成 Markdown 报告', false)
  .option('--save-snapshot', '保存快照供后续对比', false)
  .option('--compare', '与上次快照对比', false)
  .option('--output <dir>', '报告输出目录', 'reports')
  .option('--no-browser', '跳过浏览器指纹检测', false)
  .option('--gui', '启动 Web GUI', false)
  .action(async (options) => {
    // 如果是 GUI 模式，启动 Web 服务器
    if (options.gui) {
      console.log(chalk.cyan('正在启动 Web GUI...'));
      require('./server');
      return;
    }

    console.log('');
    console.log(chalk.bold.magenta(`  🛡️  ${APP_NAME} v${VERSION}`));
    console.log(chalk.gray('  AI平台环境指纹自检工具'));
    console.log(chalk.gray('  ────────────────────────────────'));
    console.log('');

    const engine = new ScanEngine();
    const spinner = ora({ text: '初始化扫描引擎...', color: 'cyan' }).start();

    try {
      // 运行扫描
      const skipBrowser = !options.full || options.noBrowser;
      
      const report = await engine.runFullScan(skipBrowser, (progress) => {
        spinner.text = `[${progress.percentage}%] 正在检测: ${progress.currentModule}`;
      });

      spinner.succeed(chalk.green(`扫描完成! 共 ${report.allItems.length} 项检测，耗时 ${report.totalDuration}ms`));
      console.log('');

      // 显示评分
      const riskLabel = getRiskLabel(report.riskLevel);
      const riskChalk = report.riskLevel === RiskLevel.SAFE ? chalk.green
        : report.riskLevel === RiskLevel.CAUTION ? chalk.yellow
        : report.riskLevel === RiskLevel.HIGH ? chalk.hex('#f97316')
        : chalk.red;

      console.log(chalk.bold('  ╔══════════════════════════════════╗'));
      console.log(chalk.bold(`  ║  风险评分:  ${riskChalk.bold(String(report.totalRisk).padStart(3))} / 100  ${riskChalk.bold(riskLabel.padEnd(6))}  ║`));
      console.log(chalk.bold('  ╚══════════════════════════════════╝'));
      console.log('');

      // 分类统计
      console.log(chalk.bold('  检测统计:'));
      console.log(`    ${chalk.green('✅')} 安全项: ${chalk.green(String(report.stats.safeCount))}`);
      console.log(`    ${chalk.yellow('⚠️')}  注意项: ${chalk.yellow(String(report.stats.cautionCount))}`);
      console.log(`    ${chalk.hex('#f97316')('🔶')} 高风险: ${chalk.hex('#f97316')(String(report.stats.highCount))}`);
      console.log(`    ${chalk.red('🔴')} 严重:   ${chalk.red(String(report.stats.criticalCount))}`);
      console.log('');

      // 显示各模块摘要
      console.log(chalk.bold('  模块详情:'));
      for (const mod of report.modules) {
        const modRiskChalk = mod.risk <= 25 ? chalk.green
          : mod.risk <= 50 ? chalk.yellow
          : mod.risk <= 75 ? chalk.hex('#f97316')
          : chalk.red;
        
        const status = mod.success ? modRiskChalk(`${mod.risk}%`) : chalk.red('失败');
        console.log(`    ${mod.success ? '●' : '✗'} ${mod.moduleName.padEnd(20)} ${status.padEnd(15)} ${chalk.gray(mod.summary.substring(0, 50))}`);
      }
      console.log('');

      // 显示高风险项
      const highRiskItems = report.allItems.filter(i => i.risk >= 6);
      if (highRiskItems.length > 0) {
        console.log(chalk.bold.red(`  ⚠️  高风险项 (${highRiskItems.length} 项):`));
        for (const item of highRiskItems.slice(0, 10)) {
          console.log(`    ${chalk.red('•')} [${item.risk}/10] ${item.name}: ${chalk.gray(item.description.substring(0, 60))}`);
          if (item.fix) {
            console.log(`      ${chalk.cyan('修复:')} ${item.fix}`);
          }
        }
        if (highRiskItems.length > 10) {
          console.log(chalk.gray(`    ... 还有 ${highRiskItems.length - 10} 项，查看完整报告获取详情`));
        }
        console.log('');
      }

      // 生成报告
      const reportGen = new ReportGenerator();
      const generateAny = options.html || options.json || options.md;
      
      if (generateAny || options.full) {
        const outputDir = path.resolve(options.output);
        const files = await reportGen.generateAll(report, outputDir);
        
        console.log(chalk.bold('  📄 报告已生成:'));
        if (options.html || options.full) console.log(`    HTML: ${chalk.cyan(files.html)}`);
        if (options.md || options.full) console.log(`    Markdown: ${chalk.cyan(files.md)}`);
        if (options.json || options.full) console.log(`    JSON: ${chalk.cyan(files.json)}`);
        console.log('');

        // 自动打开 HTML 报告
        if (options.html || options.full) {
          try {
            const open = require('open');
            await open(files.html);
          } catch {}
        }
      }

      // 保存快照
      if (options.saveSnapshot) {
        const snapshotMgr = new SnapshotManager();
        const snapPath = await snapshotMgr.save(report);
        console.log(chalk.bold(`  📸 快照已保存: ${chalk.cyan(snapPath)}`));
        console.log('');
      }

      // 与上次快照对比
      if (options.compare) {
        const snapshotMgr = new SnapshotManager();
        const previous = await snapshotMgr.getLatest();
        if (previous) {
          const diff = snapshotMgr.compare(previous, report);
          console.log(chalk.bold('  📊 快照对比:'));
          console.log(`    评分变化: ${diff.scoreDelta > 0 ? chalk.red(`+${diff.scoreDelta}`) : diff.scoreDelta < 0 ? chalk.green(`${diff.scoreDelta}`) : chalk.gray('无变化')}`);
          console.log(`    新增风险: ${diff.newRisks.length} 项`);
          console.log(`    已解决:   ${diff.resolvedRisks.length} 项`);
          console.log(`    变化项:   ${diff.changedItems.length} 项`);
          console.log('');
        } else {
          console.log(chalk.yellow('  ⚠️  未找到历史快照，请先使用 --save-snapshot 保存'));
          console.log('');
        }
      }

      console.log(chalk.gray('  ────────────────────────────────'));
      console.log(chalk.gray(`  ${APP_NAME} v${VERSION} — 纯本地运行，无数据上传`));
      console.log('');

    } catch (error: any) {
      spinner.fail(chalk.red(`扫描出错: ${error.message}`));
      console.error(error);
      process.exit(1);
    }
  });

program.parse(process.argv);
