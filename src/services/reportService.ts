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

const generateVulnerabilitySection = (vuln: Vulnerability, index: number): string => {
  return `
    <div class="vulnerability-section">
      <div class="vulnerability-table">
        <div class="vulnerability-header">
          <h2 class="vulnerability-title">${index + 1}. ${vuln.title}</h2>
        </div>
        
        <div class="rating-row">
          <div class="rating-cell" style="background-color: ${getSeverityColor(vuln.severity)}">
            Risk Rating: ${vuln.severity}
            ${vuln.count ? `<br>Total Occurrences: ${vuln.count}` : ''}
          </div>
          <div class="cvss-cell">CVSS Score: ${vuln.cvss}</div>
        </div>
        
        <table width="100%">
          <tr>
            <td style="width: 30%; background-color: #f5f5f5;"><strong>Plugin ID:</strong></td>
            <td>${vuln.pluginId}</td>
          </tr>
          <tr>
            <td style="width: 30%; background-color: #f5f5f5;"><strong>Description:</strong></td>
            <td>${vuln.description}</td>
          </tr>
          <tr>
            <td style="width: 30%; background-color: #f5f5f5;"><strong>Potential Impact:</strong></td>
            <td>
              <ul class="recommendation-list">
                <li>Unauthorized data access or manipulation</li>
                <li>System compromise</li>
                <li>Service disruption</li>
                <li>Compliance violations</li>
              </ul>
            </td>
          </tr>
          <tr>
            <td style="width: 30%; background-color: #f5f5f5;"><strong>Remediation Steps:</strong></td>
            <td>
              <div class="recommendation-list">
                ${vuln.solution}
              </div>
            </td>
          </tr>
        </table>
      </div>
    </div>
  `;
};

const getSeverityColor = (severity: string): string => {
  switch (severity.toLowerCase()) {
    case 'critical':
      return '#ea384c';
    case 'high':
      return '#f97316';
    case 'medium':
      return '#eab308';
    case 'low':
      return '#22c55e';
    default:
      return '#3b82f6';
  }
};

const generateReportHeader = (companyDetails: CompanyDetails): string => {
  return `
    <html>
    <head>
    <style>
      @page {
        margin: 2cm;
      }
      body { 
        font-family: Arial, sans-serif;
        line-height: 1.6;
        color: #1A1F2C;
      }
      .header { 
        text-align: center;
        padding: 40px 20px;
        border-bottom: 3px solid #1A1F2C;
        margin-bottom: 40px;
      }
      .vulnerability-section {
        page-break-before: always;
        margin-top: 40px;
      }
      .vulnerability-table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      }
      .vulnerability-header {
        background-color: #f5f5f5;
        padding: 20px;
        border-bottom: 2px solid #1A1F2C;
      }
      .vulnerability-title {
        font-size: 24px;
        margin: 0;
        color: #1A1F2C;
      }
      .rating-row {
        display: grid;
        grid-template-columns: 1fr 1fr;
      }
      .rating-cell {
        color: white;
        padding: 15px;
        font-weight: bold;
        text-align: center;
      }
      .cvss-cell {
        padding: 15px;
        background-color: #f5f5f5;
        text-align: center;
        font-weight: bold;
      }
      td {
        padding: 15px;
        border: 1px solid #ddd;
      }
      .severity-group {
        page-break-before: always;
      }
      .severity-header {
        font-size: 28px;
        color: #1A1F2C;
        margin: 40px 0;
        padding: 20px;
        background-color: #f5f5f5;
        border-left: 5px solid #1A1F2C;
      }
      .executive-summary {
        margin: 40px 0;
        padding: 30px;
        background-color: #f8f9fa;
        border-radius: 8px;
      }
      .summary-table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      }
      .summary-table th,
      .summary-table td {
        padding: 15px;
        border: 1px solid #ddd;
        text-align: left;
      }
      .summary-table th {
        background-color: #f5f5f5;
        font-weight: bold;
      }
      .recommendation-list {
        margin: 15px 0;
        padding-left: 20px;
      }
      .recommendation-list li {
        margin-bottom: 10px;
        line-height: 1.6;
      }
    </style>
    </head>
    <body>
      <div class="header">
        <h1 style="font-size: 32px; margin-bottom: 10px;">${companyDetails.companyName}</h1>
        <h2 style="font-size: 24px; color: #666;">Vulnerability Assessment Report</h2>
        <p style="margin-top: 20px; color: #666;">
          Date: ${companyDetails.reportDate.toLocaleDateString()}<br>
          Prepared By: ${companyDetails.preparedBy}
        </p>
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
    <div class="executive-summary">
      <h2 style="color: #1A1F2C;">EXECUTIVE SUMMARY</h2>
      <table class="summary-table">
        <tr>
          <th>Category</th>
          <th>Count</th>
        </tr>
        <tr>
          <td>Total Hosts Analyzed</td>
          <td>${mergedHosts.length}</td>
        </tr>
        <tr style="background-color: #ea384c; color: white;">
          <td>Critical Vulnerabilities</td>
          <td>${vulnerabilityTotals.critical}</td>
        </tr>
        <tr style="background-color: #f97316; color: white;">
          <td>High Vulnerabilities</td>
          <td>${vulnerabilityTotals.high}</td>
        </tr>
        <tr style="background-color: #eab308; color: white;">
          <td>Medium Vulnerabilities</td>
          <td>${vulnerabilityTotals.medium}</td>
        </tr>
        <tr style="background-color: #22c55e; color: white;">
          <td>Low Vulnerabilities</td>
          <td>${vulnerabilityTotals.low}</td>
        </tr>
        <tr style="background-color: #3b82f6; color: white;">
          <td>Informational Findings</td>
          <td>${vulnerabilityTotals.info}</td>
        </tr>
      </table>
    </div>
  `;

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  let globalIndex = 1;

  severityOrder.forEach(severity => {
    const severityVulns = mergedHosts.flatMap(host => 
      host.vulnerabilities[severity as keyof typeof host.vulnerabilities]
    );

    if (severityVulns.length > 0) {
      reportContent += `
        <div class="severity-group">
          <h2 class="severity-header">${severity.toUpperCase()} Severity Vulnerabilities</h2>
      `;

      severityVulns.forEach(vuln => {
        reportContent += generateVulnerabilitySection(vuln, globalIndex);
        globalIndex++;
      });

      reportContent += '</div>';
    }
  });

  reportContent += '</body></html>';

  if (onProgress) {
    onProgress(100);
  }

  return new Blob([reportContent], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });
};
