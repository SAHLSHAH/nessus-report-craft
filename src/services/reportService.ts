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
      body { font-family: Arial, sans-serif; }
      .header { 
        background-color: #1A1F2C;
        color: white;
        padding: 20px;
        display: flex;
        align-items: center;
      }
      .company-info {
        margin-left: 20px;
      }
      table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
      }
      th {
        background-color: #8B5CF6;
        color: white;
        padding: 10px;
        text-align: left;
      }
      td {
        padding: 8px;
        border: 1px solid #ddd;
      }
      .severity-critical { color: #ea384c; }
      .severity-high { color: #f97316; }
      .severity-medium { color: #eab308; }
      .severity-low { color: #22c55e; }
      .severity-info { color: #3b82f6; }
    </style>
    </head>
    <body>
      <div class="header">
        <img src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3Qgd2lkdGg9IjEwMCIgaGVpZ2h0PSIxMDAiIGZpbGw9IiMxQTFGMkMiLz4KPHRleHQgeD0iNTAiIHk9IjUwIiBmb250LWZhbWlseT0iQXJpYWwiIGZvbnQtc2l6ZT0iNDAiIGZpbGw9IndoaXRlIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBhbGlnbm1lbnQtYmFzZWxpbmU9Im1pZGRsZSI+JHtjb21wYW55RGV0YWlscy5jb21wYW55TmFtZS5jaGFyQXQoMCl9PC90ZXh0Pgo8L3N2Zz4=" width="100" height="100" />
        <div class="company-info">
          <h1>${companyDetails.companyName}</h1>
          <p>Date: ${companyDetails.reportDate.toLocaleDateString()}</p>
          <p>Prepared By: ${companyDetails.preparedBy}</p>
        </div>
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
    <table>
      <tr>
        <th>Category</th>
        <th>Count</th>
      </tr>
      <tr>
        <td>Total Hosts Analyzed</td>
        <td>${mergedHosts.length}</td>
      </tr>
      <tr>
        <td>Critical Vulnerabilities</td>
        <td class="severity-critical">${vulnerabilityTotals.critical}</td>
      </tr>
      <tr>
        <td>High Vulnerabilities</td>
        <td class="severity-high">${vulnerabilityTotals.high}</td>
      </tr>
      <tr>
        <td>Medium Vulnerabilities</td>
        <td class="severity-medium">${vulnerabilityTotals.medium}</td>
      </tr>
      <tr>
        <td>Low Vulnerabilities</td>
        <td class="severity-low">${vulnerabilityTotals.low}</td>
      </tr>
      <tr>
        <td>Informational Findings</td>
        <td class="severity-info">${vulnerabilityTotals.info}</td>
      </tr>
    </table>
  `;

  mergedHosts.forEach(host => {
    reportContent += `
      <h2 style="color: #1A1F2C; margin-top: 30px;">HOST: ${host.ip} (${host.hostname})</h2>
      
      ${['critical', 'high', 'medium', 'low', 'info'].map(severity => {
        const vulns = host.vulnerabilities[severity as keyof typeof host.vulnerabilities];
        if (vulns.length === 0) return '';
        
        return `
          <h3 class="severity-${severity}" style="margin-top: 20px;">
            ${severity.toUpperCase()} VULNERABILITIES (${vulns.length})
          </h3>
          <table>
            <tr>
              <th>Plugin ID</th>
              <th>Title</th>
              <th>CVSS</th>
              <th>Count</th>
            </tr>
            ${vulns.map(vuln => `
              <tr>
                <td>${vuln.pluginId}</td>
                <td>
                  <strong>${vuln.title}</strong>
                  <p style="margin: 5px 0; color: #666;">${vuln.description}</p>
                  <p style="margin: 5px 0; color: #444;"><strong>Solution:</strong> ${vuln.solution}</p>
                </td>
                <td>${vuln.cvss}</td>
                <td>${vuln.count || 1}</td>
              </tr>
            `).join('')}
          </table>
        `;
      }).join('')}
    `;
  });

  reportContent += `
    <h2 style="color: #1A1F2C; margin-top: 30px;">REMEDIATION RECOMMENDATIONS</h2>
    <table>
      <tr>
        <th>Priority</th>
        <th>Actions</th>
      </tr>
      <tr>
        <td style="background-color: #fef2f2;">High Priority</td>
        <td>
          <ul>
            <li>Address all Critical and High vulnerabilities immediately</li>
            <li>Focus on vulnerabilities with highest occurrence counts first</li>
          </ul>
        </td>
      </tr>
      <tr>
        <td style="background-color: #fffbeb;">Medium Priority</td>
        <td>
          <ul>
            <li>Schedule remediation for Medium vulnerabilities within 30 days</li>
            <li>Group similar vulnerabilities for efficient patching cycles</li>
          </ul>
        </td>
      </tr>
      <tr>
        <td style="background-color: #f0fdf4;">Low Priority</td>
        <td>
          <ul>
            <li>Document Low and Informational findings</li>
            <li>Address during regular maintenance windows</li>
          </ul>
        </td>
      </tr>
    </table>
    </body>
    </html>
  `;

  completedSteps++;
  if (onProgress) {
    onProgress(100);
  }

  return new Blob([reportContent], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });
};
