/**
 * AzureScan — Web GUI 服务器
 * Express 本地 Web 服务，提供完整的扫描控制和报告查看界面
 */

import express from 'express';
import path from 'path';
import { ScanEngine } from './scanner';
import { ReportGenerator } from './utils/report-generator';
import { SnapshotManager } from './utils/snapshot';
import { SERVER, VERSION, PATHS } from './config';
import { ScanReport, APIResponse, ScanProgress } from './types';
import fs from 'fs-extra';

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// 全局状态
let currentScan: {
  running: boolean;
  progress: ScanProgress | null;
  lastReport: ScanReport | null;
} = {
  running: false,
  progress: null,
  lastReport: null,
};

const engine = new ScanEngine();
const reportGen = new ReportGenerator();
const snapshotMgr = new SnapshotManager();

// ============================================================
// API 路由
// ============================================================

/** 获取服务状态 */
app.get('/api/status', (_req, res) => {
  res.json({
    success: true,
    data: {
      version: VERSION,
      scanning: currentScan.running,
      progress: currentScan.progress,
      hasLastReport: !!currentScan.lastReport,
    },
    timestamp: new Date().toISOString(),
  } as APIResponse);
});

/** 启动扫描 */
app.post('/api/scan', async (req, res) => {
  if (currentScan.running) {
    res.json({ success: false, error: '扫描正在进行中', timestamp: new Date().toISOString() } as APIResponse);
    return;
  }

  const skipBrowser = req.body?.skipBrowser !== false; // 默认跳过浏览器
  currentScan.running = true;
  currentScan.progress = null;

  res.json({ success: true, data: { message: '扫描已启动' }, timestamp: new Date().toISOString() } as APIResponse);

  // 异步执行扫描
  try {
    const report = await engine.runFullScan(skipBrowser, (progress) => {
      currentScan.progress = progress;
    });
    currentScan.lastReport = report;

    // 自动保存快照
    try {
      await snapshotMgr.save(report);
    } catch {}

    // 自动生成报告文件
    try {
      await reportGen.generateAll(report);
    } catch {}

  } catch (error: any) {
    console.error('扫描出错:', error);
    currentScan.progress = {
      currentModule: '出错',
      completedModules: [],
      totalModules: 0,
      percentage: 0,
      status: 'error',
    };
  } finally {
    currentScan.running = false;
  }
});

/** 获取扫描进度 */
app.get('/api/progress', (_req, res) => {
  res.json({
    success: true,
    data: {
      running: currentScan.running,
      progress: currentScan.progress,
    },
    timestamp: new Date().toISOString(),
  } as APIResponse);
});

/** 获取最新扫描结果 */
app.get('/api/report', (_req, res) => {
  if (!currentScan.lastReport) {
    res.json({ success: false, error: '暂无扫描结果', timestamp: new Date().toISOString() } as APIResponse);
    return;
  }
  res.json({
    success: true,
    data: currentScan.lastReport,
    timestamp: new Date().toISOString(),
  } as APIResponse);
});

/** 获取 HTML 报告 */
app.get('/api/report/html', (_req, res) => {
  if (!currentScan.lastReport) {
    res.status(404).send('暂无扫描结果');
    return;
  }
  const html = reportGen.generateHTML(currentScan.lastReport);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

/** 获取快照列表 */
app.get('/api/snapshots', async (_req, res) => {
  const list = await snapshotMgr.listAll();
  res.json({ success: true, data: list, timestamp: new Date().toISOString() } as APIResponse);
});

/** 与上次快照对比 */
app.get('/api/compare', async (_req, res) => {
  if (!currentScan.lastReport) {
    res.json({ success: false, error: '暂无当前扫描结果', timestamp: new Date().toISOString() } as APIResponse);
    return;
  }

  const snapshots = await snapshotMgr.listAll();
  if (snapshots.length < 2) {
    res.json({ success: false, error: '需要至少 2 次快照才能对比', timestamp: new Date().toISOString() } as APIResponse);
    return;
  }

  // 加载倒数第二个快照
  const prevFile = snapshots[1].filename;
  try {
    const previous = await fs.readJson(path.join(PATHS.fingerprints, prevFile));
    const diff = snapshotMgr.compare(previous, currentScan.lastReport);
    res.json({ success: true, data: diff, timestamp: new Date().toISOString() } as APIResponse);
  } catch (error: any) {
    res.json({ success: false, error: error.message, timestamp: new Date().toISOString() } as APIResponse);
  }
});

/** 获取报告文件列表 */
app.get('/api/reports', async (_req, res) => {
  try {
    await fs.ensureDir(PATHS.reports);
    const files = (await fs.readdir(PATHS.reports))
      .filter(f => f.endsWith('.html'))
      .sort()
      .reverse();
    res.json({ success: true, data: files, timestamp: new Date().toISOString() } as APIResponse);
  } catch (err: any) {
    res.json({ success: false, error: err.message, timestamp: new Date().toISOString() } as APIResponse);
  }
});

/** 读取历史报告 HTML */
app.get('/api/reports/:filename', async (req, res) => {
  const filepath = path.join(PATHS.reports, req.params.filename);
  if (!(await fs.pathExists(filepath))) {
    res.status(404).send('报告不存在');
    return;
  }
  const html = await fs.readFile(filepath, 'utf-8');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

// ============================================================
// 启动服务器
// ============================================================
app.listen(SERVER.port, SERVER.host, () => {
  const url = `http://${SERVER.host}:${SERVER.port}`;
  console.log('');
  console.log(`  🛡️  AzureScan Web GUI v${VERSION}`);
  console.log(`  ────────────────────────────────`);
  console.log(`  ➜  打开浏览器访问: \x1b[36m${url}\x1b[0m`);
  console.log(`  ➜  按 Ctrl+C 停止服务`);
  console.log('');

  // 尝试自动打开浏览器
  try {
    const open = require('open');
    open(url);
  } catch {}
});

export default app;
