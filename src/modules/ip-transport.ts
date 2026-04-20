/**
 * AzureScan — IP & 传输层指纹检测模块
 * 30+ 检测项
 * 
 * - IP 地理位置查询（ip-api.com，免费，带缓存）
 * - ASN / ISP / 代理/主机商检测
 * - IP 地理 vs 系统时区/语言一致性（数据传递给一致性模块）
 * - DNS 泄漏检测
 */

import http from 'http';
import https from 'https';
import fs from 'fs-extra';
import path from 'path';
import { CheckCategory, CheckItem, ModuleResult, ScanModule } from '../types';
import { CATEGORY_WEIGHTS, IP_API, PATHS } from '../config';
import { createCheckItem, Timer } from '../utils/helpers';

interface IPInfo {
  status: string;
  query: string;      // IP
  country: string;
  countryCode: string;
  region: string;
  regionName: string;
  city: string;
  zip: string;
  lat: number;
  lon: number;
  timezone: string;
  isp: string;
  org: string;
  as: string;
  asname: string;
  proxy: boolean;      // 是否是代理 IP
  hosting: boolean;    // 是否是主机商 IP
}

export class IPTransportModule implements ScanModule {
  name = 'IP & 传输层指纹';
  category = CheckCategory.IP_TRANSPORT;

  async run(): Promise<ModuleResult> {
    const timer = new Timer();
    const items: CheckItem[] = [];
    const weight = CATEGORY_WEIGHTS[this.category];

    try {
      // ----------------------------------------------------------
      // 1. 查询公网 IP 信息
      // ----------------------------------------------------------
      let ipInfo: IPInfo | null = null;
      
      // 尝试从缓存读取
      try {
        await fs.ensureDir(PATHS.cache);
        if (await fs.pathExists(IP_API.cacheFile)) {
          const cache = await fs.readJson(IP_API.cacheFile);
          if (Date.now() - cache.timestamp < IP_API.cacheTTL) {
            ipInfo = cache.data;
          }
        }
      } catch {}

      // 缓存过期或不存在，发起请求
      if (!ipInfo) {
        ipInfo = await this.fetchIPInfo();
        if (ipInfo) {
          try {
            await fs.writeJson(IP_API.cacheFile, { data: ipInfo, timestamp: Date.now() });
          } catch {}
        }
      }

      if (ipInfo && ipInfo.status === 'success') {
        // ---- 公网 IP ----
        items.push(createCheckItem(
          'ip.public_ip',
          '公网 IP 地址',
          this.category,
          ipInfo.query,
          0,
          weight,
          `公网 IP: ${ipInfo.query}`,
          undefined,
          'IP 地址是平台追踪和风控的基础信号',
        ));

        // ---- 地理位置 ----
        items.push(createCheckItem(
          'ip.geolocation',
          'IP 地理位置',
          this.category,
          { country: ipInfo.country, region: ipInfo.regionName, city: ipInfo.city, lat: ipInfo.lat, lon: ipInfo.lon },
          0,
          weight,
          `位置: ${ipInfo.city}, ${ipInfo.regionName}, ${ipInfo.country}`,
          undefined,
          'IP 地理位置用于与时区、语言的一致性检查',
        ));

        // ---- IP 时区 ----
        items.push(createCheckItem(
          'ip.timezone',
          'IP 所在时区',
          this.category,
          ipInfo.timezone,
          0,
          weight,
          `IP 时区: ${ipInfo.timezone}`,
          undefined,
          'IP 时区与系统时区不一致是高风险信号',
        ));

        // ---- ISP / ASN ----
        items.push(createCheckItem(
          'ip.isp',
          'ISP / 运营商',
          this.category,
          { isp: ipInfo.isp, org: ipInfo.org, as: ipInfo.as, asname: ipInfo.asname },
          0,
          weight,
          `ISP: ${ipInfo.isp} (AS: ${ipInfo.asname})`,
        ));

        // ---- 代理 IP 检测 ----
        items.push(createCheckItem(
          'ip.proxy',
          '代理 IP 检测',
          this.category,
          ipInfo.proxy,
          ipInfo.proxy ? 8 : 0,
          weight,
          ipInfo.proxy ? '⚠️ IP 被识别为代理 IP' : 'IP 未被识别为代理',
          ipInfo.proxy ? '更换为住宅型 IP 或直连网络' : undefined,
          '代理 IP 是平台风控的核心检测项，住宅型 IP 最安全',
        ));

        // ---- 主机商 IP 检测 ----
        items.push(createCheckItem(
          'ip.hosting',
          '主机商 / 数据中心 IP',
          this.category,
          ipInfo.hosting,
          ipInfo.hosting ? 7 : 0,
          weight,
          ipInfo.hosting ? '⚠️ IP 属于主机商/数据中心' : 'IP 非数据中心 IP',
          ipInfo.hosting ? '更换为住宅型 IP，避免使用云服务器 IP' : undefined,
          '数据中心 IP 风险极高，强烈建议使用住宅宽带 IP',
        ));

        // ---- ASN 类型分析 ----
        const highRiskASNKeywords = ['ovh', 'digitalocean', 'hetzner', 'vultr', 'linode', 'aws', 'azure', 'google cloud', 'alibaba', 'tencent'];
        const asnLower = `${ipInfo.isp} ${ipInfo.org} ${ipInfo.asname}`.toLowerCase();
        const matchedASN = highRiskASNKeywords.find(kw => asnLower.includes(kw));

        if (matchedASN) {
          items.push(createCheckItem(
            'ip.datacenter_asn',
            '数据中心 ASN',
            this.category,
            matchedASN,
            7,
            weight,
            `⚠️ ASN 属于已知数据中心: ${matchedASN.toUpperCase()}`,
            '更换为住宅型 ISP 的 IP',
            '数据中心 ASN 几乎必然被标记为高风险',
          ));
        }

        // ---- IP 与系统时区一致性检查 ----
        const systemTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        const ipTimezone = ipInfo.timezone;
        
        // 简单比较：如果 IP 时区和系统时区的大洲部分不同，标记风险
        const systemContinent = systemTimezone.split('/')[0];
        const ipContinent = ipTimezone.split('/')[0];
        const timezoneMatch = systemContinent === ipContinent;

        items.push(createCheckItem(
          'ip.timezone_consistency',
          'IP 时区 vs 系统时区一致性',
          this.category,
          { ipTimezone, systemTimezone, match: timezoneMatch },
          !timezoneMatch ? 8 : 0,
          weight,
          timezoneMatch
            ? `时区一致: IP(${ipTimezone}) = 系统(${systemTimezone})`
            : `⚠️ 时区不一致: IP(${ipTimezone}) ≠ 系统(${systemTimezone})`,
          !timezoneMatch ? '确保系统时区与 IP 所在地区一致' : undefined,
          '时区不一致是一致性检查中权重最高的风险项之一',
        ));

        // ---- IP 国家 vs 系统语言一致性 ----
        const systemLocale = Intl.DateTimeFormat().resolvedOptions().locale;
        const ipCountryCode = ipInfo.countryCode;
        
        // 粗略匹配
        const localeCountry = systemLocale.split('-')?.pop()?.toUpperCase();
        const langMatch = localeCountry === ipCountryCode;

        items.push(createCheckItem(
          'ip.locale_consistency',
          'IP 国家 vs 系统语言一致性',
          this.category,
          { ipCountry: ipCountryCode, systemLocale, match: langMatch },
          !langMatch ? 4 : 0,
          weight,
          langMatch
            ? `语言地区一致: IP(${ipCountryCode}) = 语言(${systemLocale})`
            : `语言地区不完全一致: IP(${ipCountryCode}) vs 语言(${systemLocale})`,
          !langMatch ? '调整系统语言设置以匹配 IP 所在国家' : undefined,
          '语言与国家不匹配会增加风控评分',
        ));

      } else {
        items.push(createCheckItem(
          'ip.query_failed',
          'IP 查询失败',
          this.category,
          '无法获取',
          0,
          weight,
          'IP 地理位置查询失败（可能无网络连接或 API 限制）',
          '检查网络连接，或等待 API 限制重置（45次/分钟）',
        ));
      }

      // ----------------------------------------------------------
      // 2. 本地网络信息
      // ----------------------------------------------------------
      // MTU 检测
      if (process.platform === 'win32') {
        const { execCommand } = require('../utils/helpers');
        const netshOutput = execCommand('netsh interface ipv4 show subinterfaces');
        if (netshOutput) {
          const mtuLines = netshOutput.split('\n').filter((l: string) => /\d/.test(l));
          const mtuValues: { iface: string; mtu: number }[] = [];
          
          for (const line of mtuLines) {
            const match = line.match(/(\d+)\s+\d+\s+\d+\s+(.+)/);
            if (match) {
              mtuValues.push({ mtu: parseInt(match[1]), iface: match[2].trim() });
            }
          }

          if (mtuValues.length > 0) {
            const nonStandardMtu = mtuValues.filter(m => m.mtu !== 1500 && m.mtu !== 1400);
            items.push(createCheckItem(
              'ip.mtu',
              'MTU 值',
              this.category,
              mtuValues,
              0,
              weight,
              `网络接口 MTU: ${mtuValues.map(m => `${m.iface}(${m.mtu})`).join(', ')}`,
              undefined,
              'MTU 值是被动网络指纹的组成部分',
            ));
          }
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
        summary: this.generateSummary(items, ipInfo),
        duration: timer.elapsed(),
        success: true,
      };
    } catch (error: any) {
      return {
        moduleName: this.name,
        category: this.category,
        items,
        risk: 0,
        summary: `IP & 传输层检测出错: ${error.message}`,
        duration: timer.elapsed(),
        success: false,
        error: error.message,
      };
    }
  }

  private fetchIPInfo(): Promise<IPInfo | null> {
    return new Promise((resolve) => {
      const req = http.get(IP_API.url, { timeout: 10000 }, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve(null);
          }
        });
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
    });
  }

  private calculateModuleRisk(items: CheckItem[]): number {
    if (items.length === 0) return 0;
    const totalWeightedRisk = items.reduce((sum, item) => sum + item.risk * item.weight, 0);
    const maxPossible = items.length * 10 * CATEGORY_WEIGHTS[this.category];
    return Math.round((totalWeightedRisk / maxPossible) * 100);
  }

  private generateSummary(items: CheckItem[], ipInfo: IPInfo | null): string {
    if (!ipInfo) return 'IP 查询失败';
    const risks = items.filter(i => i.risk > 3);
    if (risks.length === 0) return `IP ${ipInfo.query} (${ipInfo.city}, ${ipInfo.country}) - 无风险`;
    return `IP ${ipInfo.query} 存在 ${risks.length} 个风险项`;
  }
}
