import { CompanyDetails } from '@/components/CompanyDetailsForm';
import { XMLParser } from 'fast-xml-parser';

interface Vulnerability {
  id: string;
  pluginId: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  description: string;
  solution: string;
  cvss: string;
  count?: number; // Track how many times this vulnerability appears across files
}

interface Host {
  ip: string;
  hostname: string;
  vulnerabilities: {
    critical: Vulnerability[];
    high: Vulnerability[];
    medium: Vulnerability[];
    low: Vulnerability[];
    info: Vulnerability[];
  };
}

const parseNessusFile = async (file: File): Promise<Host[]> => {
  try {
    const fileContent = await file.text();
    
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
    });
    
    const result = parser.parse(fileContent);
    
    const nessusData = result?.NessusClientData_v2 || {};
    const report = nessusData.Report || {};
    
    const reportHosts = Array.isArray(report.ReportHost) 
      ? report.ReportHost 
      : report.ReportHost ? [report.ReportHost] : [];
      
    const hosts: Host[] = [];
    
    for (const reportHost of reportHosts) {
      const hostname = reportHost['@_name'] || '';
      
      let ip = '';
      const hostProperties = reportHost.HostProperties?.tag || [];
      
      if (Array.isArray(hostProperties)) {
        const ipTag = hostProperties.find((tag: any) => tag['@_name'] === 'host-ip');
        ip = ipTag?.['#text'] || hostname;
      } else if (hostProperties && typeof hostProperties === 'object') {
        ip = hostProperties['@_name'] === 'host-ip' ? hostProperties['#text'] : hostname;
      }
      
      const reportItems = Array.isArray(reportHost.ReportItem) 
        ? reportHost.ReportItem 
        : reportHost.ReportItem ? [reportHost.ReportItem] : [];
        
      const vulnerabilities: {
        critical: Vulnerability[];
        high: Vulnerability[];
        medium: Vulnerability[];
        low: Vulnerability[];
        info: Vulnerability[];
      } = {
        critical: [],
        high: [],
        medium: [],
        low: [],
        info: []
      };
      
      for (const item of reportItems) {
        let severityCategory: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
        const severityValue = parseInt(item['@_severity'] || '0');
        
        switch (severityValue) {
          case 4:
            severityCategory = 'Critical';
            break;
          case 3:
            severityCategory = 'High';
            break;
          case 2:
            severityCategory = 'Medium';
            break;
          case 1:
            severityCategory = 'Low';
            break;
          default:
            severityCategory = 'Info';
        }
        
        const vulnerability: Vulnerability = {
          id: item['@_id'] || Math.random().toString(36).substring(2, 10),
          pluginId: item['@_pluginID'] || '',
          title: item['@_pluginName'] || 'Unknown Vulnerability',
          severity: severityCategory,
          description: item.description || 'No description provided',
          solution: item.solution || 'No solution provided',
          cvss: item.cvss_base_score || item.cvss_vector || '0.0',
          count: 1
        };
        
        vulnerabilities[severityCategory.toLowerCase() as keyof typeof vulnerabilities].push(vulnerability);
      }
      
      hosts.push({
        ip,
        hostname,
        vulnerabilities
      });
    }
    
    return hosts;
  } catch (error) {
    console.error('Error parsing Nessus file:', error);
    throw new Error(`Failed to parse ${file.name}: ${error}`);
  }
};

const mergeHosts = (hostArrays: Host[][]): Host[] => {
  const hostMap = new Map<string, Host>();
  
  for (const hostArray of hostArrays) {
    for (const host of hostArray) {
      if (hostMap.has(host.ip)) {
        const existingHost = hostMap.get(host.ip)!;
        
        existingHost.vulnerabilities.critical = mergeAndCountVulnerabilities(
          existingHost.vulnerabilities.critical, 
          host.vulnerabilities.critical
        );
        
        existingHost.vulnerabilities.high = mergeAndCountVulnerabilities(
          existingHost.vulnerabilities.high, 
          host.vulnerabilities.high
        );
        
        existingHost.vulnerabilities.medium = mergeAndCountVulnerabilities(
          existingHost.vulnerabilities.medium, 
          host.vulnerabilities.medium
        );
        
        existingHost.vulnerabilities.low = mergeAndCountVulnerabilities(
          existingHost.vulnerabilities.low, 
          host.vulnerabilities.low
        );
        
        existingHost.vulnerabilities.info = mergeAndCountVulnerabilities(
          existingHost.vulnerabilities.info, 
          host.vulnerabilities.info
        );
        
        hostMap.set(host.ip, existingHost);
      } else {
        hostMap.set(host.ip, {
          ...host,
          vulnerabilities: {
            critical: [...host.vulnerabilities.critical],
            high: [...host.vulnerabilities.high],
            medium: [...host.vulnerabilities.medium],
            low: [...host.vulnerabilities.low],
            info: [...host.vulnerabilities.info],
          }
        });
      }
    }
  }
  
  return Array.from(hostMap.values()).sort((a, b) => {
    const aSegments = a.ip.split('.').map(Number);
    const bSegments = b.ip.split('.').map(Number);
    
    for (let i = 0; i < 4; i++) {
      if (aSegments[i] !== bSegments[i]) {
        return aSegments[i] - bSegments[i];
      }
    }
    return 0;
  });
};

const mergeAndCountVulnerabilities = (existingVulns: Vulnerability[], newVulns: Vulnerability[]): Vulnerability[] => {
  const vulnMap = new Map<string, Vulnerability>();
  
  existingVulns.forEach(vuln => {
    vulnMap.set(vuln.pluginId, { ...vuln });
  });
  
  newVulns.forEach(vuln => {
    if (vulnMap.has(vuln.pluginId)) {
      const existingVuln = vulnMap.get(vuln.pluginId)!;
      existingVuln.count = (existingVuln.count || 1) + 1;
      vulnMap.set(vuln.pluginId, existingVuln);
    } else {
      vulnMap.set(vuln.pluginId, { ...vuln, count: 1 });
    }
  });
  
  return Array.from(vulnMap.values()).sort((a, b) => {
    if ((b.count || 1) !== (a.count || 1)) {
      return (b.count || 1) - (a.count || 1);
    }
    return parseFloat(b.cvss) - parseFloat(a.cvss);
  });
};

const calculateVulnerabilityTotals = (hosts: Host[]): Record<string, number> => {
  const totals = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  
  hosts.forEach(host => {
    totals.critical += host.vulnerabilities.critical.length;
    totals.high += host.vulnerabilities.high.length;
    totals.medium += host.vulnerabilities.medium.length;
    totals.low += host.vulnerabilities.low.length;
    totals.info += host.vulnerabilities.info.length;
  });
  
  return totals;
};

const generateReportHeader = (companyDetails: CompanyDetails): string => {
  return `
    <html>
    <head>
    <style>
      body { 
        font-family: Arial, sans-serif;
        line-height: 1.6;
        color: #333;
      }
      .header { 
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 20px;
        border-bottom: 2px solid #000;
      }
      .company-logo {
        max-width: 200px;
        max-height: 100px;
      }
      .vulnerability-table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
        border: 1px solid #000;
      }
      .vulnerability-header {
        background-color: #f5f5f5;
        padding: 10px;
        border: 1px solid #000;
      }
      .vulnerability-title {
        font-size: 16px;
        color: #ea384c;
        margin: 0;
        padding: 10px;
        border-bottom: 1px solid #000;
      }
      .rating-row {
        display: flex;
      }
      .rating-cell {
        background-color: #ea384c;
        color: white;
        padding: 8px;
        width: 50%;
        border: 1px solid #000;
      }
      .cvss-cell {
        padding: 8px;
        width: 50%;
        border: 1px solid #000;
      }
      td {
        padding: 8px;
        border: 1px solid #000;
      }
      .severity-critical { background-color: #ea384c; color: white; }
      .severity-high { background-color: #f97316; color: white; }
      .severity-medium { background-color: #eab308; color: white; }
      .severity-low { background-color: #22c55e; color: white; }
      .severity-info { background-color: #3b82f6; color: white; }
      .recommendation-list {
        list-style-type: decimal;
        padding-left: 20px;
      }
      .poc-section img {
        max-width: 100%;
        border: 1px solid #ddd;
        margin-top: 10px;
      }
    </style>
    </head>
    <body>
      <div class="header">
        ${companyDetails.companyLogo ? 
          `<img src="${companyDetails.companyLogo}" alt="Company Logo" class="company-logo" />` :
          ''
        }
        <div>
          <h1>${companyDetails.companyName}</h1>
          <p>Date: ${companyDetails.reportDate.toLocaleDateString()}</p>
          <p>Prepared By: ${companyDetails.preparedBy}</p>
        </div>
      </div>
  `;
};

const generateVulnerabilitySection = (vuln: Vulnerability, index: number): string => {
  return `
    <div class="vulnerability-table">
      <div class="vulnerability-header">
        <h2 class="vulnerability-title">${index + 1}. Vulnerability Name: ${vuln.title}</h2>
      </div>
      
      <div class="rating-row">
        <div class="rating-cell">Vulnerability Rating: ${vuln.severity}</div>
        <div class="cvss-cell">CVSS: ${vuln.cvss}</div>
      </div>
      
      <table width="100%">
        <tr>
          <td><strong>OWASP Category:</strong></td>
          <td>Security Misconfiguration</td>
        </tr>
        <tr>
          <td><strong>URL:</strong></td>
          <td>${vuln.pluginId}</td>
        </tr>
        <tr>
          <td><strong>Description:</strong></td>
          <td>${vuln.description}</td>
        </tr>
        <tr>
          <td><strong>Impact:</strong></td>
          <td>
            - Potential security breach<br>
            - Data exposure risk<br>
            - Compliance violations
          </td>
        </tr>
        <tr>
          <td><strong>Recommendation:</strong></td>
          <td>${vuln.solution}</td>
        </tr>
      </table>
    </div>
  `;
};

export const generateReport = async (
  files: File[],
  companyDetails: CompanyDetails,
  onProgress?: (progress: number) => void
): Promise<Blob> => {
  const totalSteps = files.length + 3;
  let completedSteps = 0;
  
  const parsedHostArrays: Host[][] = [];
  for (let i = 0; i < files.length; i++) {
    try {
      const parsedHosts = await parseNessusFile(files[i]);
      parsedHostArrays.push(parsedHosts);
      completedSteps++;
      if (onProgress) {
        onProgress(Math.floor((completedSteps / totalSteps) * 100));
      }
    } catch (error) {
      console.error(`Error processing file ${files[i].name}:`, error);
      if (onProgress) {
        onProgress(Math.floor((completedSteps / totalSteps) * 100));
      }
    }
  }
  
  const mergedHosts = mergeHosts(parsedHostArrays);
  completedSteps++;
  if (onProgress) {
    onProgress(Math.floor((completedSteps / totalSteps) * 100));
  }
  
  const vulnerabilityTotals = calculateVulnerabilityTotals(mergedHosts);
  completedSteps++;
  if (onProgress) {
    onProgress(Math.floor((completedSteps / totalSteps) * 100));
  }
  
  let reportContent = generateReportHeader(companyDetails);
  
  reportContent += `
    <h2 style="color: #1A1F2C; margin-top: 30px;">EXECUTIVE SUMMARY</h2>
    <table class="vulnerability-table">
      <tr>
        <th>Category</th>
        <th>Count</th>
      </tr>
      <tr>
        <td>Total Hosts Analyzed</td>
        <td>${mergedHosts.length}</td>
      </tr>
      <tr class="severity-critical">
        <td>Critical Vulnerabilities</td>
        <td>${vulnerabilityTotals.critical}</td>
      </tr>
      <tr class="severity-high">
        <td>High Vulnerabilities</td>
        <td>${vulnerabilityTotals.high}</td>
      </tr>
      <tr class="severity-medium">
        <td>Medium Vulnerabilities</td>
        <td>${vulnerabilityTotals.medium}</td>
      </tr>
      <tr class="severity-low">
        <td>Low Vulnerabilities</td>
        <td>${vulnerabilityTotals.low}</td>
      </tr>
      <tr class="severity-info">
        <td>Informational Findings</td>
        <td>${vulnerabilityTotals.info}</td>
      </tr>
    </table>
  `;

  reportContent += `<h2 style="color: #1A1F2C; margin-top: 30px;">DETAILED FINDINGS</h2>`;
  
  mergedHosts.forEach(host => {
    const allVulnerabilities = [
      ...host.vulnerabilities.critical,
      ...host.vulnerabilities.high,
      ...host.vulnerabilities.medium,
      ...host.vulnerabilities.low,
      ...host.vulnerabilities.info
    ];

    allVulnerabilities.forEach((vuln, index) => {
      reportContent += generateVulnerabilitySection(vuln, index);
    });
  });

  reportContent += `</body></html>`;

  if (onProgress) {
    onProgress(100);
  }

  return new Blob([reportContent], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });
};
