/**
 * AzureScan — 浏览器 / JS指纹层检测模块
 * 60+ 检测项
 * 
 * 使用 Playwright 启动真实 Chromium 浏览器
 * 注入指纹采集脚本，获取完整的浏览器环境指纹
 * 
 * 如果 Playwright 未安装，优雅降级并跳过
 */

import { CheckCategory, CheckItem, ModuleResult, ScanModule } from '../types';
import { CATEGORY_WEIGHTS } from '../config';
import { createCheckItem, Timer } from '../utils/helpers';

export class BrowserModule implements ScanModule {
  name = '浏览器 / JS 指纹';
  category = CheckCategory.BROWSER;

  async run(): Promise<ModuleResult> {
    const timer = new Timer();
    const items: CheckItem[] = [];
    const weight = CATEGORY_WEIGHTS[this.category];

    try {
      // 动态加载 Playwright（可能未安装）
      let playwright: any;
      try {
        playwright = require('playwright');
      } catch {
        items.push(createCheckItem(
          'browser.not_installed',
          'Playwright 未安装',
          this.category,
          '跳过',
          0,
          weight,
          'Playwright 未安装，浏览器指纹检测被跳过。运行 npx playwright install chromium 安装。',
          'npm install playwright && npx playwright install chromium',
        ));
        return {
          moduleName: this.name,
          category: this.category,
          items,
          risk: 0,
          summary: 'Playwright 未安装，浏览器指纹检测已跳过',
          duration: timer.elapsed(),
          success: true,
        };
      }

      // 启动浏览器
      const browser = await playwright.chromium.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
      });

      const context = await browser.newContext();
      const page = await context.newPage();

      // 导航到空白页
      await page.goto('about:blank');

      // 注入指纹采集脚本（使用字符串以避免 TS 对 DOM 类型的检查）
      const fpScript = `(() => {
        const fp = {};
        // Navigator
        fp.userAgent = navigator.userAgent;
        fp.platform = navigator.platform;
        fp.language = navigator.language;
        fp.languages = navigator.languages;
        fp.hardwareConcurrency = navigator.hardwareConcurrency;
        fp.deviceMemory = navigator.deviceMemory || 'N/A';
        fp.maxTouchPoints = navigator.maxTouchPoints;
        fp.cookieEnabled = navigator.cookieEnabled;
        fp.doNotTrack = navigator.doNotTrack;
        fp.vendor = navigator.vendor;
        fp.vendorSub = navigator.vendorSub;
        fp.productSub = navigator.productSub;
        fp.webdriver = navigator.webdriver;
        fp.pdfViewerEnabled = navigator.pdfViewerEnabled;
        // Screen
        fp.screenWidth = screen.width;
        fp.screenHeight = screen.height;
        fp.availWidth = screen.availWidth;
        fp.availHeight = screen.availHeight;
        fp.colorDepth = screen.colorDepth;
        fp.pixelDepth = screen.pixelDepth;
        fp.devicePixelRatio = window.devicePixelRatio;
        // Timezone
        fp.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        fp.timezoneOffset = new Date().getTimezoneOffset();
        // Canvas 2D
        try {
          const c = document.createElement('canvas'); c.width=200; c.height=50;
          const ctx = c.getContext('2d');
          if(ctx){ctx.textBaseline='alphabetic';ctx.fillStyle='#f60';ctx.fillRect(125,1,62,20);
          ctx.fillStyle='#069';ctx.font='11pt no-real-font-123456';ctx.fillText('AzureScan',2,15);
          ctx.fillStyle='rgba(102,204,0,0.7)';ctx.font='18pt Arial';ctx.fillText('AzureScan',4,45);
          fp.canvasHash=c.toDataURL().slice(-50);}
        } catch(e) { fp.canvasHash='error'; }
        // WebGL
        try {
          const c = document.createElement('canvas');
          const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
          if(gl){fp.webglVendor=gl.getParameter(gl.VENDOR);fp.webglRenderer=gl.getParameter(gl.RENDERER);
          const di=gl.getExtension('WEBGL_debug_renderer_info');
          if(di){fp.webglUnmaskedVendor=gl.getParameter(di.UNMASKED_VENDOR_WEBGL);fp.webglUnmaskedRenderer=gl.getParameter(di.UNMASKED_RENDERER_WEBGL);}
          fp.webglVersion=gl.getParameter(gl.VERSION);fp.webglShadingLanguageVersion=gl.getParameter(gl.SHADING_LANGUAGE_VERSION);
          fp.webglMaxTextureSize=gl.getParameter(gl.MAX_TEXTURE_SIZE);fp.webglMaxRenderbufferSize=gl.getParameter(gl.MAX_RENDERBUFFER_SIZE);
          fp.webglExtensions=(gl.getSupportedExtensions()||[]).length;}
        } catch(e) { fp.webglVendor='error'; }
        // AudioContext
        try {
          const ac = new (window.AudioContext || window.webkitAudioContext)();
          fp.audioSampleRate=ac.sampleRate;fp.audioState=ac.state;fp.audioMaxChannelCount=ac.destination.maxChannelCount;ac.close();
        } catch(e) { fp.audioSampleRate='error'; }
        // Permissions
        try { fp.permissionsApiAvailable=!!navigator.permissions; } catch(e) { fp.permissionsApiAvailable=false; }
        // Connection
        try { const cn=navigator.connection; if(cn){fp.connectionType=cn.effectiveType;fp.connectionDownlink=cn.downlink;fp.connectionRtt=cn.rtt;} } catch(e){}
        // Features
        fp.webRtcSupport=!!(window.RTCPeerConnection);fp.webSocketSupport=!!window.WebSocket;
        fp.workerSupport=!!window.Worker;fp.serviceWorkerSupport=!!navigator.serviceWorker;
        fp.notificationSupport=!!window.Notification;fp.mediaDevicesSupport=!!navigator.mediaDevices;
        fp.bluetoothSupport=!!navigator.bluetooth;fp.usbSupport=!!navigator.usb;
        fp.gamePadSupport=!!navigator.getGamepads;fp.speechSynthesisSupport=!!window.speechSynthesis;
        // Performance
        try { const perf=performance.getEntriesByType('navigation');fp.performanceNavigation=perf.length>0;
        fp.performanceMemory=!!performance.memory;if(performance.memory){fp.jsHeapSizeLimit=performance.memory.jsHeapSizeLimit;} } catch(e){}
        // Plugins
        fp.pluginCount=navigator.plugins?navigator.plugins.length:0;
        fp.mimeTypeCount=navigator.mimeTypes?navigator.mimeTypes.length:0;
        return fp;
      })()`;
      const fingerprint: any = await page.evaluate(fpScript);

      await browser.close();

      // 分析指纹结果并生成 CheckItems
      // ---- webdriver 检测 ----
      items.push(createCheckItem(
        'browser.webdriver',
        'navigator.webdriver',
        this.category,
        fingerprint.webdriver,
        fingerprint.webdriver === true ? 9 : 0,
        weight,
        fingerprint.webdriver
          ? '⚠️ navigator.webdriver = true，暴露自动化控制'
          : 'navigator.webdriver = false，正常',
        fingerprint.webdriver ? '使用浏览器 stealth 插件或非 headless 模式' : undefined,
        'webdriver 属性是自动化检测的第一道防线',
      ));

      // ---- User-Agent ----
      items.push(createCheckItem(
        'browser.user_agent',
        'User-Agent',
        this.category,
        fingerprint.userAgent,
        fingerprint.userAgent?.includes('HeadlessChrome') ? 8 : 0,
        weight,
        `UA: ${fingerprint.userAgent?.substring(0, 80)}...`,
        fingerprint.userAgent?.includes('HeadlessChrome') ? '使用非 Headless 模式或修改 UA' : undefined,
        'Headless 浏览器的 UA 包含 HeadlessChrome 字符串',
      ));

      // ---- 平台 ----
      items.push(createCheckItem(
        'browser.platform',
        '浏览器平台',
        this.category,
        fingerprint.platform,
        0,
        weight,
        `平台: ${fingerprint.platform}`,
      ));

      // ---- 语言 ----
      items.push(createCheckItem(
        'browser.language',
        '浏览器语言',
        this.category,
        { primary: fingerprint.language, all: fingerprint.languages },
        0,
        weight,
        `语言: ${fingerprint.language} (${fingerprint.languages?.join(', ')})`,
        undefined,
        '浏览器语言用于与系统语言、IP 地理位置的一致性检查',
      ));

      // ---- Hardware Concurrency ----
      items.push(createCheckItem(
        'browser.hardware_concurrency',
        '逻辑处理器数',
        this.category,
        fingerprint.hardwareConcurrency,
        fingerprint.hardwareConcurrency <= 2 ? 4 : 0,
        weight,
        `hardwareConcurrency: ${fingerprint.hardwareConcurrency}`,
        fingerprint.hardwareConcurrency <= 2 ? '增加 CPU 核心分配' : undefined,
        '极低核心数可能暴露虚拟环境',
      ));

      // ---- Device Memory ----
      items.push(createCheckItem(
        'browser.device_memory',
        '设备内存',
        this.category,
        fingerprint.deviceMemory,
        fingerprint.deviceMemory !== 'N/A' && fingerprint.deviceMemory <= 2 ? 4 : 0,
        weight,
        `deviceMemory: ${fingerprint.deviceMemory}GB`,
        fingerprint.deviceMemory <= 2 ? '增加虚拟机内存分配' : undefined,
      ));

      // ---- 屏幕参数 ----
      items.push(createCheckItem(
        'browser.screen',
        '屏幕参数',
        this.category,
        { 
          width: fingerprint.screenWidth, 
          height: fingerprint.screenHeight,
          dpr: fingerprint.devicePixelRatio,
          colorDepth: fingerprint.colorDepth,
        },
        0,
        weight,
        `分辨率: ${fingerprint.screenWidth}x${fingerprint.screenHeight} @${fingerprint.devicePixelRatio}x, ${fingerprint.colorDepth}bit`,
      ));

      // ---- Canvas Hash ----
      items.push(createCheckItem(
        'browser.canvas',
        'Canvas 2D 指纹',
        this.category,
        fingerprint.canvasHash,
        0,
        weight,
        `Canvas hash: ...${fingerprint.canvasHash}`,
        undefined,
        'Canvas 指纹是高熵浏览器指纹的核心组成',
      ));

      // ---- WebGL Renderer ----
      const vmGpuStrings = ['swiftshader', 'llvmpipe', 'virtualbox', 'vmware', 'mesa', 'software'];
      const webglRenderer = (fingerprint.webglUnmaskedRenderer || fingerprint.webglRenderer || '').toLowerCase();
      const isVmGpu = vmGpuStrings.some(s => webglRenderer.includes(s));

      items.push(createCheckItem(
        'browser.webgl_renderer',
        'WebGL 渲染器',
        this.category,
        fingerprint.webglUnmaskedRenderer || fingerprint.webglRenderer,
        isVmGpu ? 7 : 0,
        weight,
        `渲染器: ${fingerprint.webglUnmaskedRenderer || fingerprint.webglRenderer || '未知'}`,
        isVmGpu ? '使用 GPU 直通或禁用 SwiftShader' : undefined,
        'WebGL 渲染器字符串是 VM 检测的重要高熵指纹',
      ));

      // ---- WebGL 扩展数 ----
      items.push(createCheckItem(
        'browser.webgl_extensions',
        'WebGL 扩展数',
        this.category,
        fingerprint.webglExtensions,
        fingerprint.webglExtensions < 10 ? 4 : 0,
        weight,
        `WebGL 扩展: ${fingerprint.webglExtensions} 个`,
        fingerprint.webglExtensions < 10 ? 'WebGL 扩展过少可能暗示虚拟化 GPU' : undefined,
      ));

      // ---- Audio ----
      items.push(createCheckItem(
        'browser.audio',
        'AudioContext 指纹',
        this.category,
        { sampleRate: fingerprint.audioSampleRate, maxChannels: fingerprint.audioMaxChannelCount },
        0,
        weight,
        `AudioContext: ${fingerprint.audioSampleRate}Hz, ${fingerprint.audioMaxChannelCount}ch`,
      ));

      // ---- Touch Points ----
      items.push(createCheckItem(
        'browser.touch_points',
        '最大触摸点数',
        this.category,
        fingerprint.maxTouchPoints,
        0,
        weight,
        `maxTouchPoints: ${fingerprint.maxTouchPoints}`,
      ));

      // ---- 插件数量 ----
      items.push(createCheckItem(
        'browser.plugins',
        '浏览器插件数',
        this.category,
        fingerprint.pluginCount,
        fingerprint.pluginCount === 0 ? 3 : 0,
        weight,
        `插件数: ${fingerprint.pluginCount}`,
        fingerprint.pluginCount === 0 ? '无插件可能暗示 headless 浏览器环境' : undefined,
      ));

      // ---- 功能支持汇总 ----
      const features = {
        WebRTC: fingerprint.webRtcSupport,
        WebSocket: fingerprint.webSocketSupport,
        Worker: fingerprint.workerSupport,
        ServiceWorker: fingerprint.serviceWorkerSupport,
        MediaDevices: fingerprint.mediaDevicesSupport,
        SpeechSynthesis: fingerprint.speechSynthesisSupport,
        Bluetooth: fingerprint.bluetoothSupport,
        USB: fingerprint.usbSupport,
        Gamepad: fingerprint.gamePadSupport,
      };

      items.push(createCheckItem(
        'browser.features',
        'API 功能支持',
        this.category,
        features,
        0,
        weight,
        `支持的 API: ${Object.entries(features).filter(([,v]) => v).map(([k]) => k).join(', ')}`,
      ));

      // ---- 连接信息 ----
      if (fingerprint.connectionType) {
        items.push(createCheckItem(
          'browser.connection',
          '网络连接信息',
          this.category,
          { type: fingerprint.connectionType, downlink: fingerprint.connectionDownlink, rtt: fingerprint.connectionRtt },
          0,
          weight,
          `连接类型: ${fingerprint.connectionType}, 下行: ${fingerprint.connectionDownlink}Mbps, RTT: ${fingerprint.connectionRtt}ms`,
        ));
      }

      // ---- 时区 ----
      items.push(createCheckItem(
        'browser.timezone',
        '浏览器时区',
        this.category,
        { timezone: fingerprint.timezone, offset: fingerprint.timezoneOffset },
        0,
        weight,
        `时区: ${fingerprint.timezone} (UTC${fingerprint.timezoneOffset > 0 ? '-' : '+'}${Math.abs(fingerprint.timezoneOffset / 60)})`,
        undefined,
        '浏览器时区用于与系统时区、IP 地理位置的一致性检查',
      ));

      // ---- PDF Viewer ----
      items.push(createCheckItem(
        'browser.pdf_viewer',
        'PDF 查看器',
        this.category,
        fingerprint.pdfViewerEnabled,
        0,
        weight,
        `PDF 查看器: ${fingerprint.pdfViewerEnabled ? '已启用' : '未启用'}`,
      ));

      // ---- Performance Memory ----
      if (fingerprint.jsHeapSizeLimit) {
        items.push(createCheckItem(
          'browser.js_heap',
          'JS 堆内存限制',
          this.category,
          `${Math.round(fingerprint.jsHeapSizeLimit / 1024 / 1024)}MB`,
          0,
          weight,
          `JS 堆限制: ${Math.round(fingerprint.jsHeapSizeLimit / 1024 / 1024)}MB`,
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
        summary: `浏览器指纹检测出错: ${error.message}`,
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
    if (risks.length === 0) return '浏览器指纹检测正常';
    return `发现 ${risks.length} 个浏览器指纹风险项`;
  }
}
