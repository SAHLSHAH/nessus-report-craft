
import { CompanyDetails } from '@/components/CompanyDetailsForm';

interface Vulnerability {
  id: string;
  pluginId: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  description: string;
  solution: string;
  cvss: string;
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
        
        existingHost.vulnerabilities.critical = [
          ...existingHost.vulnerabilities.critical,
          ...host.vulnerabilities.critical
        ];
        existingHost.vulnerabilities.high = [
          ...existingHost.vulnerabilities.high,
          ...host.vulnerabilities.high
        ];
        existingHost.vulnerabilities.medium = [
          ...existingHost.vulnerabilities.medium,
          ...host.vulnerabilities.medium
        ];
        existingHost.vulnerabilities.low = [
          ...existingHost.vulnerabilities.low,
          ...host.vulnerabilities.low
        ];
        existingHost.vulnerabilities.info = [
          ...existingHost.vulnerabilities.info,
          ...host.vulnerabilities.info
        ];
        
        // Deduplicate vulnerabilities by pluginId
        existingHost.vulnerabilities.critical = deduplicateVulnerabilities(existingHost.vulnerabilities.critical);
        existingHost.vulnerabilities.high = deduplicateVulnerabilities(existingHost.vulnerabilities.high);
        existingHost.vulnerabilities.medium = deduplicateVulnerabilities(existingHost.vulnerabilities.medium);
        existingHost.vulnerabilities.low = deduplicateVulnerabilities(existingHost.vulnerabilities.low);
        existingHost.vulnerabilities.info = deduplicateVulnerabilities(existingHost.vulnerabilities.info);
        
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

// Deduplicate vulnerabilities by pluginId
const deduplicateVulnerabilities = (vulnerabilities: Vulnerability[]): Vulnerability[] => {
  const uniqueVulnerabilities = new Map<string, Vulnerability>();
  vulnerabilities.forEach(vuln => {
    uniqueVulnerabilities.set(vuln.pluginId, vuln);
  });
  return Array.from(uniqueVulnerabilities.values());
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
  completedSteps++;
  if (onProgress) {
    onProgress(Math.floor((completedSteps / totalSteps) * 100));
  }
  
  // Step 4: Generate report content
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // Generate the report content
  let reportContent = `
    NESSUS VULNERABILITY REPORT
    
    Company: ${companyDetails.companyName}
    Date: ${companyDetails.reportDate.toLocaleDateString()}
    Prepared by: ${companyDetails.preparedBy}
    
    SUMMARY:
    Total Hosts Analyzed: ${mergedHosts.length}
    Files Processed: ${files.map(file => file.name).join(', ')}
    
    VULNERABILITY FINDINGS:
    =====================================================
  `;
  
  // Add content for each host
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
    
    for (const category of categories) {
      if (category.vulns.length > 0) {
        reportContent += `\n${category.title} (${category.vulns.length}):\n`;
        reportContent += `-----------------------------------------------------\n`;
        
        category.vulns.forEach(vuln => {
          reportContent += `\n[${vuln.pluginId}] ${vuln.title}\n`;
          reportContent += `CVSS: ${vuln.cvss}\n`;
          reportContent += `Description: ${vuln.description}\n`;
          reportContent += `Solution: ${vuln.solution}\n\n`;
        });
      }
    }
  });
  
  completedSteps++;
  if (onProgress) {
    onProgress(100);
  }

  return new Blob([reportContent], { type: 'text/plain' });
};
