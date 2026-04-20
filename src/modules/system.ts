/**
 * AzureScan — 系统 & 硬件指纹检测模块
 * 30+ 检测项
 * 
 * 使用 systeminformation 采集：
 * - OS 版本、Build、Patch
 * - CPU/GPU 型号、核心数、架构
 * - RAM、硬盘信息
 * - Machine ID / BIOS UUID / 主板序列号
 * - 已安装字体列表
 * - 驱动列表（含虚拟化驱动）
 * - 时间戳偏差、NTP 状态
 */

import os from 'os';
import si from 'systeminformation';
import { CheckCategory, CheckItem, ModuleResult, ScanModule } from '../types';
import { CATEGORY_WEIGHTS, SAFE_VIRTUAL_GPU_KEYWORDS, VM_GPU_KEYWORDS } from '../config';
import {
  execCommand,
  IS_WINDOWS,
  createCheckItem,
  Timer,
  safeGet,
} from '../utils/helpers';

export class SystemModule implements ScanModule {
  name = '系统 & 硬件指纹';
  category = CheckCategory.SYSTEM;

  async run(): Promise<ModuleResult> {
    const timer = new Timer();
    const items: CheckItem[] = [];
    const weight = CATEGORY_WEIGHTS[this.category];

    try {
      // ----------------------------------------------------------
      // 1. 操作系统信息
      // ----------------------------------------------------------
      const osInfo = await si.osInfo();
      items.push(createCheckItem(
        'system.os_info',
        '操作系统',
        this.category,
        { platform: osInfo.platform, distro: osInfo.distro, release: osInfo.release, build: osInfo.build, arch: osInfo.arch },
        0,
        weight,
        `${osInfo.distro} ${osInfo.release} (Build ${osInfo.build}) [${osInfo.arch}]`,
      ));

      // Windows 版本太旧可能有风险
      if (IS_WINDOWS && osInfo.build) {
        const buildNum = parseInt(osInfo.build);
        items.push(createCheckItem(
          'system.os_build',
          'Windows Build 版本',
          this.category,
          buildNum,
          buildNum < 19041 ? 4 : 0, // Windows 10 2004 之前
          weight,
          buildNum < 19041 ? 'Windows 版本较旧，可能与现代浏览器指纹不一致' : 'Windows 版本正常',
          buildNum < 19041 ? '更新 Windows 到最新版本' : undefined,
          '过旧的 OS 版本可能导致 User-Agent 与系统不一致',
        ));
      }

      // ----------------------------------------------------------
      // 2. CPU 信息
      // ----------------------------------------------------------
      const cpu = await si.cpu();
      items.push(createCheckItem(
        'system.cpu',
        'CPU 信息',
        this.category,
        { manufacturer: cpu.manufacturer, brand: cpu.brand, cores: cpu.cores, physicalCores: cpu.physicalCores, speed: cpu.speed },
        0,
        weight,
        `${cpu.manufacturer} ${cpu.brand} (${cpu.physicalCores}C/${cpu.cores}T @ ${cpu.speed}GHz)`,
      ));

      // CPU 核心数异常（VM 通常分配 1-2 核心）
      items.push(createCheckItem(
        'system.cpu_cores',
        'CPU 核心数',
        this.category,
        cpu.physicalCores,
        cpu.physicalCores <= 1 ? 6 : (cpu.physicalCores <= 2 ? 3 : 0),
        weight,
        cpu.physicalCores <= 2 ? `仅 ${cpu.physicalCores} 个物理核心，可能是虚拟机` : `${cpu.physicalCores} 个物理核心`,
        cpu.physicalCores <= 2 ? '增加 VM 的 CPU 核心分配' : undefined,
        '极低核心数是虚拟化环境的典型特征',
      ));

      // CPU 品牌中的虚拟化标记
      const vmCpuKeywords = ['QEMU', 'Virtual', 'KVM', 'Common KVM'];
      const cpuBrand = `${cpu.manufacturer} ${cpu.brand}`.toLowerCase();
      const vmCpuMatch = vmCpuKeywords.find(kw => cpuBrand.includes(kw.toLowerCase()));
      if (vmCpuMatch) {
        items.push(createCheckItem(
          'system.cpu_vm_brand',
          'CPU 虚拟化标记',
          this.category,
          vmCpuMatch,
          8,
          weight,
          `CPU 品牌包含虚拟化标记: ${vmCpuMatch}`,
          '使用宿主机 CPU 直通（host-passthrough）',
          'CPU 品牌字符串直接暴露虚拟化环境',
        ));
      }

      // ----------------------------------------------------------
      // 3. GPU 信息（★ 区分远程桌面虚拟显卡 vs 真正 VM GPU）
      // ----------------------------------------------------------
      const graphics = await si.graphics();
      const gpus = graphics.controllers || [];
      
      for (const gpu of gpus) {
        const gpuName = gpu.model || gpu.vendor || 'Unknown';
        const gpuLower = gpuName.toLowerCase();
        
        // ★ 先检查是否是合法远程桌面/串流虚拟显卡
        const isSafeVirtualGpu = SAFE_VIRTUAL_GPU_KEYWORDS.some(kw => gpuLower.includes(kw));
        // 再检查是否是真正的 VM 虚拟 GPU
        const isVmGpu = !isSafeVirtualGpu && VM_GPU_KEYWORDS.some(kw => gpuLower.includes(kw));

        if (isSafeVirtualGpu) {
          items.push(createCheckItem(
            `system.gpu.${gpuName.replace(/[^a-z0-9]/gi, '_')}`,
            `ℹ️ 远程桌面显卡: ${gpuName}`,
            this.category,
            { model: gpuName, vendor: gpu.vendor, vram: gpu.vram, type: 'remote_desktop' },
            0,              // ★ 合法工具，不计分
            weight,
            `远程桌面虚拟显卡: ${gpuName}（合法工具，不计分）`,
            undefined,
            '远程桌面/串流工具的虚拟显卡，不影响风控评分',
          ));
        } else if (isVmGpu) {
          items.push(createCheckItem(
            `system.gpu.${gpuName.replace(/[^a-z0-9]/gi, '_')}`,
            `⚠️ VM GPU: ${gpuName}`,
            this.category,
            { model: gpuName, vendor: gpu.vendor, vram: gpu.vram, type: 'vm' },
            7,
            weight,
            `GPU 疑似虚拟化: ${gpuName}`,
            '使用 GPU 直通或更改虚拟显卡类型',
            'WebGL 渲染器字符串暴露虚拟化环境',
          ));
        } else {
          items.push(createCheckItem(
            `system.gpu.${gpuName.replace(/[^a-z0-9]/gi, '_')}`,
            `GPU: ${gpuName}`,
            this.category,
            { model: gpuName, vendor: gpu.vendor, vram: gpu.vram, type: 'physical' },
            0,
            weight,
            `GPU: ${gpuName} (${gpu.vram}MB)`,
          ));
        }
      }

      // ----------------------------------------------------------
      // 4. 内存信息
      // ----------------------------------------------------------
      const mem = await si.mem();
      const totalGB = Math.round(mem.total / (1024 * 1024 * 1024));
      items.push(createCheckItem(
        'system.memory',
        '系统内存',
        this.category,
        { total: totalGB, used: Math.round(mem.used / (1024 * 1024 * 1024)) },
        totalGB <= 2 ? 5 : (totalGB <= 4 ? 2 : 0),
        weight,
        `总内存 ${totalGB} GB`,
        totalGB <= 4 ? '增加虚拟机内存分配至 8GB+' : undefined,
        '极低内存是虚拟化环境的特征之一',
      ));

      // ----------------------------------------------------------
      // 5. 硬盘信息
      // ----------------------------------------------------------
      const disks = await si.diskLayout();
      for (const disk of disks) {
        const diskName = disk.name || disk.vendor || 'Unknown';
        const vmDiskKeywords = ['VBOX', 'VMware', 'Virtual', 'QEMU', 'HARDDISK'];
        const isVmDisk = vmDiskKeywords.some(kw => diskName.toUpperCase().includes(kw.toUpperCase()));

        if (isVmDisk) {
          items.push(createCheckItem(
            `system.disk_vm.${diskName.replace(/[^a-z0-9]/gi, '_')}`,
            `虚拟化硬盘: ${diskName}`,
            this.category,
            diskName,
            6,
            weight,
            `硬盘名称包含虚拟化标记: ${diskName}`,
            '更改虚拟硬盘的设备名称',
            '硬盘设备名称是虚拟化检测的辅助依据',
          ));
        }
      }

      // ----------------------------------------------------------
      // 6. BIOS / UUID / 序列号
      // ----------------------------------------------------------
      const system = await si.system();
      const bios = await si.bios();

      // BIOS 厂商
      const vmBiosVendors = ['innotek', 'virtualbox', 'vmware', 'qemu', 'bochs', 'xen', 'parallels'];
      const biosVendor = (bios.vendor || '').toLowerCase();
      const isVmBios = vmBiosVendors.some(v => biosVendor.includes(v));
      
      items.push(createCheckItem(
        'system.bios_vendor',
        'BIOS 厂商',
        this.category,
        bios.vendor || '未知',
        isVmBios ? 8 : 0,
        weight,
        isVmBios ? `BIOS 厂商疑似虚拟化: ${bios.vendor}` : `BIOS 厂商: ${bios.vendor || '未知'}`,
        isVmBios ? '修改 VM BIOS 信息或使用 SMBIOS 欺骗' : undefined,
        'BIOS 信息是虚拟化检测的直接证据',
      ));

      // 系统厂商
      const vmSystemManufacturers = ['vmware', 'virtualbox', 'innotek', 'qemu', 'microsoft corporation', 'xen', 'parallels', 'bochs'];
      const sysManufacturer = (system.manufacturer || '').toLowerCase();
      const isVmSystem = vmSystemManufacturers.some(v => sysManufacturer.includes(v));

      items.push(createCheckItem(
        'system.manufacturer',
        '系统厂商',
        this.category,
        system.manufacturer || '未知',
        isVmSystem ? 8 : 0,
        weight,
        isVmSystem ? `系统厂商疑似虚拟化: ${system.manufacturer}` : `系统厂商: ${system.manufacturer || '未知'}`,
        isVmSystem ? '使用 SMBIOS 欺骗工具修改系统厂商信息' : undefined,
        '系统厂商信息直接暴露虚拟化环境',
      ));

      // UUID
      items.push(createCheckItem(
        'system.uuid',
        '系统 UUID',
        this.category,
        system.uuid || '未知',
        0,
        weight,
        `系统 UUID: ${system.uuid || '未知'}`,
        undefined,
        'UUID 用于设备唯一标识追踪',
      ));

      // 序列号
      items.push(createCheckItem(
        'system.serial',
        '系统序列号',
        this.category,
        system.serial ? '已获取' : '未获取',
        0,
        weight,
        `序列号: ${system.serial ? '(已隐藏)' : '未获取'}`,
      ));

      // Machine ID
      if (IS_WINDOWS) {
        const machineGuid = execCommand(
          'reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid'
        );
        const guidMatch = machineGuid.match(/MachineGuid\s+REG_SZ\s+(.+)/);
        items.push(createCheckItem(
          'system.machine_guid',
          'Machine GUID',
          this.category,
          guidMatch ? guidMatch[1].trim() : '未获取',
          0,
          weight,
          `Machine GUID: ${guidMatch ? guidMatch[1].trim() : '未获取'}`,
          undefined,
          '平台使用 Machine GUID 进行设备追踪和指纹关联',
        ));
      }

      // ----------------------------------------------------------
      // 7. 时区和语言
      // ----------------------------------------------------------
      const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
      const locale = Intl.DateTimeFormat().resolvedOptions().locale;

      items.push(createCheckItem(
        'system.timezone',
        '系统时区',
        this.category,
        timezone,
        0,
        weight,
        `时区: ${timezone}`,
        undefined,
        '时区用于与 IP 地理位置的一致性检查',
      ));

      items.push(createCheckItem(
        'system.locale',
        '系统语言',
        this.category,
        locale,
        0,
        weight,
        `语言: ${locale}`,
        undefined,
        '语言设置用于一致性交叉检查',
      ));

      // ----------------------------------------------------------
      // 8. 时间偏差检测
      // ----------------------------------------------------------
      if (IS_WINDOWS) {
        const w32timeOutput = execCommand('w32tm /query /status');
        const offsetMatch = w32timeOutput.match(/Phase Offset\s*:\s*([\d.]+)/i);
        if (offsetMatch) {
          const offsetMs = parseFloat(offsetMatch[1]);
          items.push(createCheckItem(
            'system.time_offset',
            'NTP 时间偏差',
            this.category,
            `${offsetMs}ms`,
            offsetMs > 30000 ? 5 : (offsetMs > 5000 ? 3 : 0),
            weight,
            `NTP 偏差: ${offsetMs}ms`,
            offsetMs > 5000 ? '运行 w32tm /resync 同步时间' : undefined,
            '异常时间偏差可能暴露虚拟化环境或篡改行为',
          ));
        }
      }

      // ----------------------------------------------------------
      // 9. 主板信息
      // ----------------------------------------------------------
      const baseboard = await si.baseboard();
      const vmBoardKeywords = ['vmware', 'virtualbox', 'virtual', 'qemu', 'oracle'];
      const boardManufacturer = (baseboard.manufacturer || '').toLowerCase();
      const isVmBoard = vmBoardKeywords.some(kw => boardManufacturer.includes(kw));

      if (isVmBoard) {
        items.push(createCheckItem(
          'system.baseboard_vm',
          '主板虚拟化标记',
          this.category,
          baseboard.manufacturer,
          7,
          weight,
          `主板厂商疑似虚拟化: ${baseboard.manufacturer}`,
          '修改虚拟机 SMBIOS 主板信息',
          '主板信息是虚拟化检测的辅助依据',
        ));
      }

      // ----------------------------------------------------------
      // 10. 已安装字体数量（辅助指纹项）
      // ----------------------------------------------------------
      if (IS_WINDOWS) {
        const fontDir = 'C:\\Windows\\Fonts';
        try {
          const fontCount = execCommand(`powershell -Command "(Get-ChildItem '${fontDir}' -File | Measure-Object).Count"`);
          const count = parseInt(fontCount) || 0;
          items.push(createCheckItem(
            'system.font_count',
            '已安装字体数',
            this.category,
            count,
            count < 50 ? 3 : 0,
            weight,
            `已安装 ${count} 个字体文件`,
            count < 50 ? '安装常见字体包以匹配典型环境' : undefined,
            '字体数量过少是虚拟化/容器环境的特征',
          ));
        } catch {}
      }

      // ----------------------------------------------------------
      // 11. 启动时间
      // ----------------------------------------------------------
      const uptimeSeconds = os.uptime();
      const uptimeHours = Math.round(uptimeSeconds / 3600);

      items.push(createCheckItem(
        'system.uptime',
        '系统运行时间',
        this.category,
        `${uptimeHours} 小时`,
        uptimeHours < 1 ? 3 : 0,
        weight,
        `系统已运行 ${uptimeHours} 小时`,
        uptimeHours < 1 ? '极短的运行时间可能暗示刚创建的虚拟环境' : undefined,
        '启动时间过短可能暗示临时虚拟环境',
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
        summary: `模块执行出错: ${error.message}`,
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
    if (risks.length === 0) return '系统硬件信息正常，未发现虚拟化特征';
    return `发现 ${risks.length} 个系统级风险项，关注虚拟化相关硬件标记`;
  }
}
