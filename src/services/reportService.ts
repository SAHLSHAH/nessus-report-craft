
import { CompanyDetails } from '@/components/CompanyDetailsForm';

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

// Simulated function to parse a Nessus file
const parseNessusFile = async (file: File): Promise<Host[]> => {
  // In a real implementation, this would actually parse XML
  // For demonstration, we'll simulate parsing with random data
  await new Promise(resolve => setTimeout(resolve, 500)); // Simulate parsing delay
  
  // Generate 1-3 random hosts per file
  const hostCount = Math.floor(Math.random() * 3) + 1;
  const hosts: Host[] = [];
  
  for (let i = 0; i < hostCount; i++) {
    const ipSegments = [10, Math.floor(Math.random() * 255), Math.floor(Math.random() * 255), Math.floor(Math.random() * 255)];
    const ip = ipSegments.join('.');
    
    hosts.push({
      ip,
      hostname: `host-${ip.replace(/\./g, '-')}.local`,
      vulnerabilities: {
        critical: generateRandomVulnerabilities('Critical', Math.floor(Math.random() * 3)),
        high: generateRandomVulnerabilities('High', Math.floor(Math.random() * 5)),
        medium: generateRandomVulnerabilities('Medium', Math.floor(Math.random() * 7)),
        low: generateRandomVulnerabilities('Low', Math.floor(Math.random() * 10)),
        info: generateRandomVulnerabilities('Info', Math.floor(Math.random() * 15)),
      }
    });
  }
  
  return hosts;
};

// Helper to generate mock vulnerability data
const generateRandomVulnerabilities = (severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info', count: number): Vulnerability[] => {
  const vulnerabilities: Vulnerability[] = [];
  
  for (let i = 0; i < count; i++) {
    const id = Math.random().toString(36).substring(2, 10);
    vulnerabilities.push({
      id,
      pluginId: Math.floor(Math.random() * 100000).toString(),
      title: `${severity} Vulnerability ${id}`,
      severity,
      description: `This is a sample ${severity.toLowerCase()} vulnerability that was detected.`,
      solution: 'Update the affected software to the latest version.',
      cvss: (Math.random() * 10).toFixed(1),
      count: 1, // Initially found once
    });
  }
  
  return vulnerabilities;
};

// Merge hosts from multiple parsed files
const mergeHosts = (hostArrays: Host[][]): Host[] => {
  const hostMap = new Map<string, Host>();
  
  // Iterate through all host arrays and merge by IP address
  for (const hostArray of hostArrays) {
    for (const host of hostArray) {
      if (hostMap.has(host.ip)) {
        // Merge vulnerabilities if the host already exists
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
        // Add new host to the map
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
  
  // Convert map back to array and sort by IP address
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

// Merge and count occurrences of vulnerabilities
const mergeAndCountVulnerabilities = (existingVulns: Vulnerability[], newVulns: Vulnerability[]): Vulnerability[] => {
  const vulnMap = new Map<string, Vulnerability>();
  
  // Process existing vulnerabilities
  existingVulns.forEach(vuln => {
    vulnMap.set(vuln.pluginId, { ...vuln });
  });
  
  // Merge and count new vulnerabilities
  newVulns.forEach(vuln => {
    if (vulnMap.has(vuln.pluginId)) {
      const existingVuln = vulnMap.get(vuln.pluginId)!;
      existingVuln.count = (existingVuln.count || 1) + 1;
      vulnMap.set(vuln.pluginId, existingVuln);
    } else {
      vulnMap.set(vuln.pluginId, { ...vuln, count: 1 });
    }
  });
  
  // Convert map back to array and sort by occurrence count (descending)
  return Array.from(vulnMap.values()).sort((a, b) => {
    // Sort by count first (higher count first)
    if ((b.count || 1) !== (a.count || 1)) {
      return (b.count || 1) - (a.count || 1);
    }
    // If counts are equal, sort by CVSS score (higher score first)
    return parseFloat(b.cvss) - parseFloat(a.cvss);
  });
};

// Calculate total vulnerability counts by severity
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

// Simulate file processing and report generation
export const generateReport = async (
  files: File[],
  companyDetails: CompanyDetails,
  onProgress?: (progress: number) => void
): Promise<Blob> => {
  // Parse each file and update progress
  const totalSteps = files.length + 3; // parsing + merging + sorting + generating
  let completedSteps = 0;
  
  // Step 1: Parse all files
  const parsedHostArrays: Host[][] = [];
  for (let i = 0; i < files.length; i++) {
    const parsedHosts = await parseNessusFile(files[i]);
    parsedHostArrays.push(parsedHosts);
    completedSteps++;
    if (onProgress) {
      onProgress(Math.floor((completedSteps / totalSteps) * 100));
    }
  }
  
  // Step 2: Merge hosts from all files
  await new Promise(resolve => setTimeout(resolve, 800));
  const mergedHosts = mergeHosts(parsedHostArrays);
  completedSteps++;
  if (onProgress) {
    onProgress(Math.floor((completedSteps / totalSteps) * 100));
  }
  
  // Step 3: Final sorting and processing
  await new Promise(resolve => setTimeout(resolve, 700));
  const vulnerabilityTotals = calculateVulnerabilityTotals(mergedHosts);
  completedSteps++;
  if (onProgress) {
    onProgress(Math.floor((completedSteps / totalSteps) * 100));
  }
  
  // Step 4: Generate report content
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // Generate the report content with formatted layout
  let reportContent = `
    NESSUS VULNERABILITY REPORT
    
    Company: ${companyDetails.companyName}
    Date: ${companyDetails.reportDate.toLocaleDateString()}
    Prepared By: ${companyDetails.preparedBy}
    
    EXECUTIVE SUMMARY:
    =====================================================
    Total Hosts Analyzed: ${mergedHosts.length}
    Files Processed: ${files.map(file => file.name).join(', ')}
    
    VULNERABILITY SUMMARY:
    - Critical Vulnerabilities: ${vulnerabilityTotals.critical}
    - High Vulnerabilities: ${vulnerabilityTotals.high}
    - Medium Vulnerabilities: ${vulnerabilityTotals.medium}
    - Low Vulnerabilities: ${vulnerabilityTotals.low}
    - Informational Findings: ${vulnerabilityTotals.info}
    
    DETAILED FINDINGS BY HOST:
    =====================================================
  `;
  
  // Add content for each host, prioritizing severity sequence
  mergedHosts.forEach(host => {
    reportContent += `\n\nHOST: ${host.ip} (${host.hostname})\n`;
    reportContent += `=====================================================\n`;
    
    const categories = [
      { title: 'CRITICAL VULNERABILITIES', vulns: host.vulnerabilities.critical },
      { title: 'HIGH VULNERABILITIES', vulns: host.vulnerabilities.high },
      { title: 'MEDIUM VULNERABILITIES', vulns: host.vulnerabilities.medium },
      { title: 'LOW VULNERABILITIES', vulns: host.vulnerabilities.low },
      { title: 'INFORMATIONAL FINDINGS', vulns: host.vulnerabilities.info }
    ];
    
    // Process each category in severity order (Critical → High → Medium → Low → Info)
    for (const category of categories) {
      if (category.vulns.length > 0) {
        reportContent += `\n${category.title} (${category.vulns.length}):\n`;
        reportContent += `-----------------------------------------------------\n`;
        
        category.vulns.forEach(vuln => {
          reportContent += `\n[${vuln.pluginId}] ${vuln.title}\n`;
          reportContent += `CVSS: ${vuln.cvss}\n`;
          if (vuln.count && vuln.count > 1) {
            reportContent += `Occurrence Count: ${vuln.count} instances\n`;
          }
          reportContent += `Description: ${vuln.description}\n`;
          reportContent += `Solution: ${vuln.solution}\n\n`;
        });
      }
    }
  });
  
  // Add remediation summary section
  reportContent += `
    REMEDIATION RECOMMENDATIONS:
    =====================================================
    
    HIGH PRIORITY:
    - Address all Critical and High vulnerabilities immediately
    - Focus on vulnerabilities with highest occurrence counts first
    
    MEDIUM PRIORITY:
    - Schedule remediation for Medium vulnerabilities within 30 days
    - Group similar vulnerabilities for efficient patching cycles
    
    LOW PRIORITY:
    - Document Low and Informational findings
    - Address during regular maintenance windows
  `;
  
  completedSteps++;
  if (onProgress) {
    onProgress(100);
  }

  // Return a Word document-like format (in real implementation, this would create an actual .docx file)
  return new Blob([reportContent], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });
};
