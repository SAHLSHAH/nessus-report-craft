
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
      <div class="vulnerability-header">
        <h2 class="vulnerability-title">${index + 1}. ${vuln.title}</h2>
      </div>
      
      <div class="rating-row">
        <div class="rating-cell" style="background-color: ${getSeverityColor(vuln.severity)}">
          <strong>Risk Rating:</strong> ${vuln.severity}
          ${vuln.count && vuln.count > 1 ? `<br>Total Occurrences: ${vuln.count}` : ''}
        </div>
        <div class="cvss-cell"><strong>CVSS Score:</strong> ${vuln.cvss}</div>
      </div>
      
      <table class="details-table" width="100%">
        <tr>
          <td class="label-cell"><strong>Plugin ID:</strong></td>
          <td>${vuln.pluginId}</td>
        </tr>
        <tr>
          <td class="label-cell"><strong>Description:</strong></td>
          <td>${formatDescription(vuln.description)}</td>
        </tr>
        <tr>
          <td class="label-cell"><strong>Potential Impact:</strong></td>
          <td>
            <ul class="impact-list">
              <li>Unauthorized data access or manipulation</li>
              <li>System compromise</li>
              <li>Service disruption</li>
              <li>Compliance violations</li>
            </ul>
          </td>
        </tr>
        <tr>
          <td class="label-cell"><strong>Remediation Steps:</strong></td>
          <td>
            <div class="recommendation-content">
              ${formatSolution(vuln.solution)}
            </div>
          </td>
        </tr>
      </table>
    </div>
  `;
};

// Format description text for better readability
const formatDescription = (description: string): string => {
  if (!description) return 'No description available';
  
  // Replace multiple newlines with paragraph breaks
  const formatted = description
    .replace(/\n{2,}/g, '</p><p>')
    .replace(/\n/g, '<br>')
    .replace(/Plugin Output :/g, '<strong>Plugin Output:</strong>');
    
  return `<p>${formatted}</p>`;
};

// Format solution text for better readability
const formatSolution = (solution: string): string => {
  if (!solution) return 'No remediation steps available';
  
  // Replace multiple newlines with paragraph breaks
  const formatted = solution
    .replace(/\n{2,}/g, '</p><p>')
    .replace(/\n/g, '<br>');
    
  return `<p>${formatted}</p>`;
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
  const templateClass = companyDetails.template || 'professional';
  
  return `
    <html>
    <head>
    <style>
      @page {
        margin: 2cm;
        size: A4 portrait;
      }
      body { 
        font-family: Calibri, Arial, sans-serif;
        line-height: 1.6;
        color: #1A1F2C;
        margin: 0;
        padding: 0;
        counter-reset: page;
      }
      .header { 
        text-align: center;
        padding: 40px 20px;
        border-bottom: 3px solid #1A1F2C;
        margin-bottom: 40px;
        page-break-after: always;
      }
      .cover-title {
        font-size: 36px;
        color: #1A1F2C;
        margin-bottom: 20px;
      }
      .cover-subtitle {
        font-size: 24px;
        color: #666;
        margin-bottom: 40px;
      }
      .cover-details {
        margin-top: 60px;
        font-size: 16px;
        color: #666;
      }
      .toc {
        page-break-after: always;
      }
      .toc-title {
        font-size: 24px;
        margin-bottom: 20px;
        border-bottom: 2px solid #1A1F2C;
        padding-bottom: 10px;
      }
      .toc-item {
        margin: 10px 0;
        display: flex;
        justify-content: space-between;
      }
      .toc-number {
        font-weight: bold;
      }
      .executive-summary {
        page-break-after: always;
      }
      .section-title {
        font-size: 24px;
        margin: 40px 0 20px;
        border-bottom: 2px solid #1A1F2C;
        padding-bottom: 10px;
      }
      .vulnerability-section {
        page-break-before: always;
        margin-top: 20px;
        margin-bottom: 30px;
      }
      .vulnerability-header {
        background-color: #f5f5f5;
        padding: 15px;
        border-bottom: 2px solid #1A1F2C;
        margin-bottom: 0;
      }
      .vulnerability-title {
        font-size: 20px;
        margin: 0;
        color: #1A1F2C;
      }
      .rating-row {
        display: grid;
        grid-template-columns: 1fr 1fr;
        margin-bottom: 0;
      }
      .rating-cell {
        color: white;
        padding: 15px;
        font-weight: normal;
        text-align: left;
      }
      .cvss-cell {
        padding: 15px;
        background-color: #f5f5f5;
        text-align: left;
        font-weight: normal;
      }
      .details-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 0;
      }
      .details-table td {
        padding: 12px 15px;
        border: 1px solid #ddd;
        vertical-align: top;
      }
      .label-cell {
        width: 25%;
        background-color: #f5f5f5;
      }
      .severity-group {
        page-break-before: always;
      }
      .severity-header {
        font-size: 28px;
        color: #fff;
        margin: 0;
        padding: 15px;
        background-color: #1A1F2C;
      }
      .summary-table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      }
      .summary-table th,
      .summary-table td {
        padding: 12px 15px;
        border: 1px solid #ddd;
        text-align: left;
      }
      .summary-table th {
        background-color: #f5f5f5;
        font-weight: bold;
      }
      .impact-list {
        margin: 10px 0;
        padding-left: 20px;
      }
      .impact-list li {
        margin-bottom: 8px;
      }
      .recommendation-content p {
        margin: 10px 0;
      }
      p {
        margin: 10px 0;
      }
      .page-number:after {
        content: counter(page);
        counter-increment: page;
      }
      .footer {
        position: fixed;
        bottom: 0;
        width: 100%;
        text-align: center;
        font-size: 10px;
        color: #666;
      }
      
      /* Template-specific styles */
      .simple .header {
        background-color: #f5f5f5;
        border-bottom: 1px solid #ddd;
      }
      .simple .section-title {
        border-bottom: 1px solid #ddd;
      }
      .simple .vulnerability-header {
        background-color: #f9f9f9;
      }
      
      .professional .header {
        background: linear-gradient(to right, #f5f5f5, #fff);
        border-bottom: 3px solid #1A1F2C;
      }
      .professional .section-title {
        color: #1A1F2C;
        border-left: 5px solid #1A1F2C;
        padding-left: 10px;
      }
      
      .executive .header {
        background-color: #1A1F2C;
        color: white;
      }
      .executive .cover-title,
      .executive .cover-subtitle {
        color: white;
      }
      .executive .section-title {
        background-color: #1A1F2C;
        color: white;
        padding: 10px;
        border: none;
      }
    </style>
    </head>
    <body class="${templateClass}">
      <div class="header">
        <h1 class="cover-title">${companyDetails.companyName}</h1>
        <h2 class="cover-subtitle">Vulnerability Assessment Report</h2>
        <div class="cover-details">
          <p>Date: ${companyDetails.reportDate.toLocaleDateString()}</p>
          <p>Prepared By: ${companyDetails.preparedBy}</p>
        </div>
      </div>
  `;
};

const generateTableOfContents = (
  vulnerabilityTotals: Record<string, number>,
  totalHosts: number
): string => {
  return `
    <div class="toc">
      <h2 class="toc-title">Table of Contents</h2>
      
      <div class="toc-item">
        <span>1. Executive Summary</span>
        <span class="toc-number">1</span>
      </div>
      <div class="toc-item">
        <span>2. Scope of Assessment</span>
        <span class="toc-number">2</span>
      </div>
      <div class="toc-item">
        <span>3. Findings Overview</span>
        <span class="toc-number">2</span>
      </div>
      
      ${vulnerabilityTotals.critical > 0 ? `
      <div class="toc-item">
        <span>4. Critical Vulnerabilities</span>
        <span class="toc-number">3</span>
      </div>
      ` : ''}
      
      ${vulnerabilityTotals.high > 0 ? `
      <div class="toc-item">
        <span>${vulnerabilityTotals.critical > 0 ? '5' : '4'}. High Vulnerabilities</span>
        <span class="toc-number">${vulnerabilityTotals.critical > 0 ? '4' : '3'}</span>
      </div>
      ` : ''}
      
      ${vulnerabilityTotals.medium > 0 ? `
      <div class="toc-item">
        <span>${(vulnerabilityTotals.critical > 0 ? 5 : 4) + (vulnerabilityTotals.high > 0 ? 1 : 0)}. Medium Vulnerabilities</span>
        <span class="toc-number">${(vulnerabilityTotals.critical > 0 ? 4 : 3) + (vulnerabilityTotals.high > 0 ? 1 : 0)}</span>
      </div>
      ` : ''}
      
      ${vulnerabilityTotals.low > 0 ? `
      <div class="toc-item">
        <span>${(vulnerabilityTotals.critical > 0 ? 5 : 4) + 
                (vulnerabilityTotals.high > 0 ? 1 : 0) + 
                (vulnerabilityTotals.medium > 0 ? 1 : 0)}. Low Vulnerabilities</span>
        <span class="toc-number">${(vulnerabilityTotals.critical > 0 ? 4 : 3) + 
                                  (vulnerabilityTotals.high > 0 ? 1 : 0) + 
                                  (vulnerabilityTotals.medium > 0 ? 1 : 0)}</span>
      </div>
      ` : ''}
      
      <div class="toc-item">
        <span>${(vulnerabilityTotals.critical > 0 ? 5 : 4) + 
                (vulnerabilityTotals.high > 0 ? 1 : 0) + 
                (vulnerabilityTotals.medium > 0 ? 1 : 0) + 
                (vulnerabilityTotals.low > 0 ? 1 : 0) + 1}. Appendix</span>
        <span class="toc-number">${(vulnerabilityTotals.critical > 0 ? 4 : 3) + 
                                  (vulnerabilityTotals.high > 0 ? 1 : 0) + 
                                  (vulnerabilityTotals.medium > 0 ? 1 : 0) + 
                                  (vulnerabilityTotals.low > 0 ? 1 : 0) + 1}</span>
      </div>
    </div>
  `;
};

const generateExecutiveSummary = (
  vulnerabilityTotals: Record<string, number>,
  totalHosts: number
): string => {
  // Calculate total vulnerabilities
  const totalVulnerabilities = 
    vulnerabilityTotals.critical +
    vulnerabilityTotals.high +
    vulnerabilityTotals.medium +
    vulnerabilityTotals.low +
    vulnerabilityTotals.info;

  // Calculate risk rating based on findings
  let riskRating = "Low";
  if (vulnerabilityTotals.critical > 0) {
    riskRating = "Critical";
  } else if (vulnerabilityTotals.high > 0) {
    riskRating = "High";
  } else if (vulnerabilityTotals.medium > 0) {
    riskRating = "Medium";
  }

  return `
    <div class="executive-summary">
      <h2 class="section-title">1. Executive Summary</h2>
      
      <p>This vulnerability assessment report presents the findings from a comprehensive security scan performed on ${totalHosts} host${totalHosts !== 1 ? 's' : ''}. The assessment identified a total of ${totalVulnerabilities} vulnerabilities of varying severity levels.</p>
      
      <p>Based on the findings, the overall security risk rating is <strong>${riskRating}</strong>.</p>
      
      <h3>Key Findings</h3>
      
      <table class="summary-table">
        <tr>
          <th>Severity</th>
          <th>Count</th>
          <th>Risk Level</th>
        </tr>
        <tr style="background-color: rgba(234, 56, 76, 0.1);">
          <td><span style="color: #ea384c; font-weight: bold;">Critical</span></td>
          <td>${vulnerabilityTotals.critical}</td>
          <td>Immediate attention required</td>
        </tr>
        <tr style="background-color: rgba(249, 115, 22, 0.1);">
          <td><span style="color: #f97316; font-weight: bold;">High</span></td>
          <td>${vulnerabilityTotals.high}</td>
          <td>Remediate within 30 days</td>
        </tr>
        <tr style="background-color: rgba(234, 179, 8, 0.1);">
          <td><span style="color: #eab308; font-weight: bold;">Medium</span></td>
          <td>${vulnerabilityTotals.medium}</td>
          <td>Remediate within 90 days</td>
        </tr>
        <tr style="background-color: rgba(34, 197, 94, 0.1);">
          <td><span style="color: #22c55e; font-weight: bold;">Low</span></td>
          <td>${vulnerabilityTotals.low}</td>
          <td>Address during regular maintenance</td>
        </tr>
        <tr style="background-color: rgba(59, 130, 246, 0.1);">
          <td><span style="color: #3b82f6; font-weight: bold;">Informational</span></td>
          <td>${vulnerabilityTotals.info}</td>
          <td>Awareness only</td>
        </tr>
      </table>
      
      <p>The findings in this report outline security vulnerabilities that could potentially be exploited by malicious actors to compromise the confidentiality, integrity, or availability of your systems and data. We recommend addressing the identified issues according to their severity level.</p>
    </div>
    
    <div class="scope-section">
      <h2 class="section-title">2. Scope of Assessment</h2>
      
      <p>This vulnerability assessment covered a total of ${totalHosts} host${totalHosts !== 1 ? 's' : ''}. The assessment was conducted using automated scanning tools to identify security vulnerabilities, misconfigurations, and outdated software that could potentially be exploited by attackers.</p>
      
      <table class="summary-table">
        <tr>
          <th>Assessment Type</th>
          <th>Details</th>
        </tr>
        <tr>
          <td>Assessment Method</td>
          <td>Automated vulnerability scanning</td>
        </tr>
        <tr>
          <td>Total Hosts Scanned</td>
          <td>${totalHosts}</td>
        </tr>
        <tr>
          <td>Tools Used</td>
          <td>Nessus Vulnerability Scanner</td>
        </tr>
      </table>
    </div>
    
    <div class="findings-overview">
      <h2 class="section-title">3. Findings Overview</h2>
      
      <p>The following chart provides a visual representation of the vulnerabilities discovered during the assessment:</p>
      
      <div style="text-align: center; margin: 20px 0;">
        <table class="summary-table" style="width: 80%; margin: 0 auto;">
          <tr>
            <th style="width: 30%;">Severity</th>
            <th>Distribution</th>
          </tr>
          <tr>
            <td style="color: #ea384c; font-weight: bold;">Critical</td>
            <td>
              <div style="background-color: #ea384c; width: ${Math.min(100, (vulnerabilityTotals.critical / totalVulnerabilities) * 100)}%; height: 20px; display: inline-block;"></div>
              <span style="margin-left: 10px;">${vulnerabilityTotals.critical} (${Math.round((vulnerabilityTotals.critical / totalVulnerabilities) * 100)}%)</span>
            </td>
          </tr>
          <tr>
            <td style="color: #f97316; font-weight: bold;">High</td>
            <td>
              <div style="background-color: #f97316; width: ${Math.min(100, (vulnerabilityTotals.high / totalVulnerabilities) * 100)}%; height: 20px; display: inline-block;"></div>
              <span style="margin-left: 10px;">${vulnerabilityTotals.high} (${Math.round((vulnerabilityTotals.high / totalVulnerabilities) * 100)}%)</span>
            </td>
          </tr>
          <tr>
            <td style="color: #eab308; font-weight: bold;">Medium</td>
            <td>
              <div style="background-color: #eab308; width: ${Math.min(100, (vulnerabilityTotals.medium / totalVulnerabilities) * 100)}%; height: 20px; display: inline-block;"></div>
              <span style="margin-left: 10px;">${vulnerabilityTotals.medium} (${Math.round((vulnerabilityTotals.medium / totalVulnerabilities) * 100)}%)</span>
            </td>
          </tr>
          <tr>
            <td style="color: #22c55e; font-weight: bold;">Low</td>
            <td>
              <div style="background-color: #22c55e; width: ${Math.min(100, (vulnerabilityTotals.low / totalVulnerabilities) * 100)}%; height: 20px; display: inline-block;"></div>
              <span style="margin-left: 10px;">${vulnerabilityTotals.low} (${Math.round((vulnerabilityTotals.low / totalVulnerabilities) * 100)}%)</span>
            </td>
          </tr>
          <tr>
            <td style="color: #3b82f6; font-weight: bold;">Info</td>
            <td>
              <div style="background-color: #3b82f6; width: ${Math.min(100, (vulnerabilityTotals.info / totalVulnerabilities) * 100)}%; height: 20px; display: inline-block;"></div>
              <span style="margin-left: 10px;">${vulnerabilityTotals.info} (${Math.round((vulnerabilityTotals.info / totalVulnerabilities) * 100)}%)</span>
            </td>
          </tr>
        </table>
      </div>
      
      <p>Each vulnerability has been analyzed and documented with details on its impact, potential exploitation scenarios, and recommended remediation steps. The following sections provide detailed information on the identified vulnerabilities grouped by severity level.</p>
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
  
  // Start building the report
  let reportContent = generateReportHeader(companyDetails);
  
  // Add table of contents
  reportContent += generateTableOfContents(vulnerabilityTotals, mergedHosts.length);
  
  // Add executive summary and overview
  reportContent += generateExecutiveSummary(vulnerabilityTotals, mergedHosts.length);
  
  // Now add each vulnerability section by severity
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  let currentSectionNumber = 4; // Starting from 4 after executive summary, scope and findings overview
  let globalIndex = 1;

  severityOrder.forEach(severity => {
    // Collect all vulnerabilities of this severity from all hosts
    const allVulnsOfSeverity = mergedHosts.flatMap(host => 
      host.vulnerabilities[severity as keyof typeof host.vulnerabilities]
    );

    // If we have vulnerabilities of this severity
    if (allVulnsOfSeverity.length > 0) {
      // Add severity section header
      reportContent += `
        <div class="severity-group">
          <h2 class="severity-header" style="background-color: ${getSeverityColor(severity)};">
            ${currentSectionNumber}. ${severity.charAt(0).toUpperCase() + severity.slice(1)} Severity Vulnerabilities
          </h2>
          <p>The following ${allVulnsOfSeverity.length} ${severity} severity vulnerabilities were identified during the assessment:</p>
      `;

      // Add each vulnerability in this severity level
      allVulnsOfSeverity.forEach((vuln, index) => {
        reportContent += generateVulnerabilitySection(vuln, globalIndex);
        globalIndex++;
      });

      reportContent += '</div>';
      currentSectionNumber++;
    }
  });

  // Add appendix
  reportContent += `
    <div class="severity-group">
      <h2 class="section-title">${currentSectionNumber}. Appendix</h2>
      
      <h3>A. Assessment Methodology</h3>
      <p>The vulnerability assessment was conducted using automated scanning tools to identify security vulnerabilities, misconfigurations, and outdated software. The assessment followed industry-standard methodologies for vulnerability identification and risk assessment.</p>
      
      <h3>B. Risk Rating Scale</h3>
      <table class="summary-table">
        <tr>
          <th>Severity</th>
          <th>Description</th>
          <th>Recommended Response</th>
        </tr>
        <tr>
          <td style="color: #ea384c; font-weight: bold;">Critical</td>
          <td>Vulnerabilities that pose an immediate threat to the environment and should be remediated as soon as possible.</td>
          <td>Immediate remediation required</td>
        </tr>
        <tr>
          <td style="color: #f97316; font-weight: bold;">High</td>
          <td>Vulnerabilities that pose a significant risk to the environment and should be remediated promptly.</td>
          <td>Remediate within 30 days</td>
        </tr>
        <tr>
          <td style="color: #eab308; font-weight: bold;">Medium</td>
          <td>Vulnerabilities that pose a moderate risk to the environment and should be remediated as part of regular maintenance.</td>
          <td>Remediate within 90 days</td>
        </tr>
        <tr>
          <td style="color: #22c55e; font-weight: bold;">Low</td>
          <td>Vulnerabilities that pose a minimal risk to the environment and can be remediated during regular maintenance cycles.</td>
          <td>Address during regular maintenance</td>
        </tr>
        <tr>
          <td style="color: #3b82f6; font-weight: bold;">Informational</td>
          <td>Findings that do not pose a security risk but are provided for awareness.</td>
          <td>No action required</td>
        </tr>
      </table>
    </div>
  `;

  // Close the document
  reportContent += `
    <div class="footer">
      <p>Vulnerability Assessment Report - ${companyDetails.companyName} - ${companyDetails.reportDate.toLocaleDateString()}</p>
      <p class="page-number">Page </p>
    </div>
    </body>
    </html>
  `;

  if (onProgress) {
    onProgress(100);
  }

  return new Blob([reportContent], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });
};
