/**
 * AzureScan — 虚拟化环境专项检测模块
 * 15+ 检测项
 * 
 * 检测内容：
 * - 注册表/文件特征（VMware Tools、VBoxGuestAdditions）
 * - Hyper-V、Docker、WSL、KVM、QEMU 特征
 * - 虚拟化相关进程和服务
 * - CPUID 虚拟化位检测
 * - 与虚拟网卡模块联动
 */

import fs from 'fs';
import { CheckCategory, CheckItem, ModuleResult, ScanModule } from '../types';
import { VM_ARTIFACTS, CATEGORY_WEIGHTS, SAFE_DRIVER_KEYWORDS, VM_DRIVER_KEYWORDS } from '../config';
import {
  execCommand,
  execPowerShell,
  IS_WINDOWS,
  IS_LINUX,
  IS_MACOS,
  createCheckItem,
  Timer,
} from '../utils/helpers';

export class VirtualizationModule implements ScanModule {
  name = '虚拟化环境专项检测';
  category = CheckCategory.VIRTUALIZATION;

  async run(): Promise<ModuleResult> {
    const timer = new Timer();
    const items: CheckItem[] = [];
    const weight = CATEGORY_WEIGHTS[this.category];

    try {
      // ----------------------------------------------------------
      // 1. VM 特征文件检测（Windows）
      // ----------------------------------------------------------
      if (IS_WINDOWS) {
        const vmFilesFound: string[] = [];
        for (const filePath of VM_ARTIFACTS.windows.files) {
          try {
            if (fs.existsSync(filePath)) {
              vmFilesFound.push(filePath);
            }
          } catch {}
        }

        items.push(createCheckItem(
          'vm.artifact_files',
          '虚拟化特征文件',
          this.category,
          vmFilesFound.length > 0 ? vmFilesFound : '未发现',
          vmFilesFound.length > 0 ? 8 : 0,
          weight,
          vmFilesFound.length > 0
            ? `发现 ${vmFilesFound.length} 个虚拟化特征文件`
            : '未发现虚拟化特征文件',
          vmFilesFound.length > 0 ? '卸载虚拟化客户端工具（如 VMware Tools、VBox Guest Additions）' : undefined,
          '虚拟化工具文件是最直接的 VM 检测方式',
        ));
      }

      // ----------------------------------------------------------
      // 2. 注册表特征检测（Windows）
      // ----------------------------------------------------------
      if (IS_WINDOWS) {
        const vmRegFound: string[] = [];
        for (const regKey of VM_ARTIFACTS.windows.registryKeys) {
          const result = execCommand(`reg query "${regKey}" 2>nul`);
          if (result && !result.includes('ERROR')) {
            vmRegFound.push(regKey);
          }
        }

        items.push(createCheckItem(
          'vm.registry_keys',
          '虚拟化注册表项',
          this.category,
          vmRegFound.length > 0 ? vmRegFound : '未发现',
          vmRegFound.length > 0 ? 8 : 0,
          weight,
          vmRegFound.length > 0
            ? `发现 ${vmRegFound.length} 个虚拟化注册表项`
            : '未发现虚拟化注册表项',
          vmRegFound.length > 0 ? '清理虚拟化相关注册表项（需谨慎操作）' : undefined,
          '注册表是 Windows 上虚拟化检测的核心途径',
        ));
      }

      // ----------------------------------------------------------
      // 3. 虚拟化进程检测
      // ----------------------------------------------------------
      if (IS_WINDOWS) {
        const taskList = execCommand('tasklist /FO CSV /NH').toLowerCase();
        const vmProcessesFound: string[] = [];
        
        for (const proc of VM_ARTIFACTS.windows.processes) {
          if (taskList.includes(proc.toLowerCase())) {
            vmProcessesFound.push(proc);
          }
        }

        items.push(createCheckItem(
          'vm.processes',
          '虚拟化进程',
          this.category,
          vmProcessesFound.length > 0 ? vmProcessesFound : '未发现',
          vmProcessesFound.length > 0 ? 8 : 0,
          weight,
          vmProcessesFound.length > 0
            ? `发现虚拟化进程: ${vmProcessesFound.join(', ')}`
            : '未发现虚拟化进程',
          vmProcessesFound.length > 0 ? '停止虚拟化客户端进程' : undefined,
          '虚拟化工具进程直接暴露 VM 环境',
        ));
      }

      // ----------------------------------------------------------
      // 4. 虚拟化服务检测（Windows）
      // ----------------------------------------------------------
      if (IS_WINDOWS) {
        const vmServicesFound: string[] = [];
        for (const service of VM_ARTIFACTS.windows.services) {
          const result = execCommand(`sc query "${service}" 2>nul`);
          if (result && result.includes('RUNNING')) {
            vmServicesFound.push(service);
          }
        }

        items.push(createCheckItem(
          'vm.services',
          '虚拟化服务',
          this.category,
          vmServicesFound.length > 0 ? vmServicesFound : '未发现',
          vmServicesFound.length > 0 ? 7 : 0,
          weight,
          vmServicesFound.length > 0
            ? `发现运行中的虚拟化服务: ${vmServicesFound.join(', ')}`
            : '未发现虚拟化服务',
          vmServicesFound.length > 0 ? '停止并禁用虚拟化服务' : undefined,
          '虚拟化服务是服务级别的 VM 检测',
        ));
      }

      // ----------------------------------------------------------
      // 5. Hyper-V 检测
      // ★ Hyper-V 作为宿主机是正常的开发工具（Docker/WSL2/Android 模拟器等依赖），不计分
      // 仅在检测到 VM Guest 特征（SMBIOS、Guest 驱动等）+ Hyper-V 时才说明在 VM 内
      // ----------------------------------------------------------
      if (IS_WINDOWS) {
        const hyperv = execCommand('systeminfo').toLowerCase();
        const hypervEnabled = hyperv.includes('hyper-v') && hyperv.includes('a hypervisor has been detected');
        
        items.push(createCheckItem(
          'vm.hyperv',
          hypervEnabled ? 'ℹ️ Hyper-V 虚拟化' : 'Hyper-V 虚拟化',
          this.category,
          hypervEnabled ? '已启用' : '未启用',
          0,              // ★ 宿主机侧 Hyper-V 不计分（Docker/WSL2 等依赖它）
          weight,
          hypervEnabled
            ? 'Hyper-V 虚拟化平台已启用（作为宿主机使用是正常的，不计分）'
            : 'Hyper-V 未启用',
          undefined,
          'Hyper-V 被 Docker Desktop、WSL2、Android 模拟器等开发工具广泛使用',
        ));
      }

      // ----------------------------------------------------------
      // 6. WSL 检测
      // ----------------------------------------------------------
      if (IS_WINDOWS) {
        const wslResult = execCommand('wsl --list --quiet 2>nul');
        const wslInstalled = wslResult.length > 0 && !wslResult.includes('not recognized');

        items.push(createCheckItem(
          'vm.wsl',
          wslInstalled ? 'ℹ️ WSL (开发工具)' : 'WSL',
          this.category,
          wslInstalled ? '已安装' : '未安装',
          0,              // ★ WSL 是合法开发工具，不计分
          weight,
          wslInstalled ? 'WSL 已安装（合法开发工具，不计分）' : 'WSL 未安装',
          undefined,
          'WSL 是标准的 Windows 开发工具',
        ));
      }

      // ----------------------------------------------------------
      // 7. Docker 检测
      // ----------------------------------------------------------
      const dockerResult = execCommand('docker --version 2>nul');
      const dockerInstalled = dockerResult.includes('Docker');

      items.push(createCheckItem(
        'vm.docker',
        dockerInstalled ? 'ℹ️ Docker (开发工具)' : 'Docker',
        this.category,
        dockerInstalled ? dockerResult : '未安装',
        0,              // ★ Docker 是合法开发工具，不计分
        weight,
        dockerInstalled ? `Docker 已安装: ${dockerResult}（合法开发工具，不计分）` : 'Docker 未安装',
        undefined,
        'Docker 是标准的开发工具',
      ));

      // Docker 是否正在运行
      if (dockerInstalled) {
        const dockerRunning = execCommand('docker info 2>nul');
        const isRunning = dockerRunning.includes('Server Version');
        
        items.push(createCheckItem(
          'vm.docker_running',
          isRunning ? 'ℹ️ Docker 运行中' : 'Docker 运行状态',
          this.category,
          isRunning ? '运行中' : '未运行',
          0,              // ★ Docker 运行中也不计分
          weight,
          isRunning ? 'Docker 正在运行（合法开发工具，不计分）' : 'Docker 未运行',
          undefined,
        ));
      }

      // ----------------------------------------------------------
      // 8. 虚拟化相关驱动（★ 区分合法工具 vs 真正 VM Guest 驱动）
      // ----------------------------------------------------------
      if (IS_WINDOWS) {
        const drivers = execCommand('driverquery /FO CSV /NH');
        const vmDriversFound: Array<{ module: string; display: string }> = [];
        const safeDriversFound: Array<{ module: string; display: string }> = [];
        
        for (const line of drivers.split('\n')) {
          const lineLower = line.toLowerCase();
          const parts = line.split(',');
          const driverModule = parts[0]?.replace(/"/g, '').trim() || '';
          const driverDisplay = parts[1]?.replace(/"/g, '').trim() || driverModule;
          if (!driverModule) continue;

          // ★ 先检查是否是安全工具驱动
          if (SAFE_DRIVER_KEYWORDS.some(kw => lineLower.includes(kw))) {
            safeDriversFound.push({ module: driverModule, display: driverDisplay });
            continue;
          }

          // 再检查是否是真正的 VM Guest 驱动
          if (VM_DRIVER_KEYWORDS.some(kw => lineLower.includes(kw))) {
            vmDriversFound.push({ module: driverModule, display: driverDisplay });
          }
        }

        // ★ VM Guest 驱动（真正的风险）
        items.push(createCheckItem(
          'vm.drivers',
          vmDriversFound.length > 0 ? '⚠️ VM Guest 驱动' : '虚拟化驱动',
          this.category,
          vmDriversFound.length > 0 ? vmDriversFound.map(d => d.display) : '未发现',
          vmDriversFound.length > 0 ? 7 : 0,
          weight,
          vmDriversFound.length > 0
            ? `发现 ${vmDriversFound.length} 个 VM Guest 驱动: ${vmDriversFound.slice(0, 5).map(d => d.display).join(', ')}${vmDriversFound.length > 5 ? '...' : ''}`
            : '未发现 VM Guest 驱动 ✓',
          vmDriversFound.length > 0 ? '卸载 VM Guest 驱动（如果不在虚拟机中运行）' : undefined,
          '仅检测真正的 VM Guest 驱动，远程桌面/组网工具的驱动不计入',
        ));

        // 合法工具驱动（仅信息，不计分）
        if (safeDriversFound.length > 0) {
          items.push(createCheckItem(
            'vm.safe_drivers',
            'ℹ️ 合法工具驱动',
            this.category,
            safeDriversFound.map(d => d.display),
            0,              // ★ 不计分
            weight,
            `${safeDriversFound.length} 个合法工具驱动（不计分）: ${safeDriversFound.slice(0, 8).map(d => d.display).join(', ')}${safeDriversFound.length > 8 ? '...' : ''}`,
            undefined,
            '远程桌面/虚拟显示/组网工具的驱动是合法的，不影响风控评分',
          ));
        }
      }

      // ----------------------------------------------------------
      // 9. SMBIOS 系统型号检测
      // ----------------------------------------------------------
      if (IS_WINDOWS) {
        const productName = execCommand('wmic csproduct get Name /value').trim();
        const vmProductKeywords = ['VMware', 'VirtualBox', 'Virtual Machine', 'KVM', 'QEMU', 'HVM', 'Bochs'];
        const productMatch = vmProductKeywords.find(kw => 
          productName.toLowerCase().includes(kw.toLowerCase())
        );

        items.push(createCheckItem(
          'vm.product_name',
          '系统产品名称',
          this.category,
          productName.replace('Name=', '') || '未知',
          productMatch ? 8 : 0,
          weight,
          productMatch
            ? `系统产品名称包含虚拟化标记: ${productName}`
            : `系统产品名称: ${productName.replace('Name=', '') || '未知'}`,
          productMatch ? '使用 SMBIOS 欺骗工具修改产品名称' : undefined,
          'SMBIOS 产品名称是虚拟化检测的关键信号',
        ));
      }

      // ----------------------------------------------------------
      // 10. 是否在容器中运行
      // ----------------------------------------------------------
      if (IS_LINUX) {
        const cgroup = execCommand('cat /proc/1/cgroup 2>/dev/null');
        const inContainer = cgroup.includes('docker') || cgroup.includes('containerd') || cgroup.includes('lxc');
        
        if (inContainer) {
          items.push(createCheckItem(
            'vm.container',
            '容器环境',
            this.category,
            '是',
            7,
            weight,
            '当前环境运行在容器中',
            '在宿主机上运行而非容器中',
            '容器环境的 cgroup 特征非常明显',
          ));
        }
      }

      // ----------------------------------------------------------
      // 11. 屏幕分辨率异常检测（VM 通常使用非标准分辨率）
      // ----------------------------------------------------------
      if (IS_WINDOWS) {
        const resolution = execPowerShell(
          "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Screen]::PrimaryScreen.Bounds | Select-Object Width,Height | Format-List"
        );
        const widthMatch = resolution.match(/Width\s*:\s*(\d+)/);
        const heightMatch = resolution.match(/Height\s*:\s*(\d+)/);
        
        if (widthMatch && heightMatch) {
          const width = parseInt(widthMatch[1]);
          const height = parseInt(heightMatch[1]);
          const commonResolutions = [
            '1920x1080', '2560x1440', '3840x2160', '1366x768',
            '1440x900', '1536x864', '1600x900', '1280x720',
            '1280x1024', '1680x1050', '2560x1600', '3440x1440',
          ];
          const currentRes = `${width}x${height}`;
          const isCommon = commonResolutions.includes(currentRes);

          items.push(createCheckItem(
            'vm.screen_resolution',
            '屏幕分辨率',
            this.category,
            currentRes,
            !isCommon ? 3 : 0,
            weight,
            `分辨率 ${currentRes} ${isCommon ? '(常见)' : '(非常见，可能是 VM)'}`,
            !isCommon ? '将虚拟机分辨率设置为常见值（如 1920x1080）' : undefined,
            '非标准分辨率是虚拟化环境的辅助检测指标',
          ));
        }
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
    if (risks.length === 0) return '未检测到虚拟化环境特征';
    return `发现 ${risks.length} 个虚拟化特征，请检查 VM 工具、驱动和注册表`;
  }
}
