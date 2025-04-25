
import { CompanyDetails } from '@/components/CompanyDetailsForm';

// Simulate file processing and report generation
export const generateReport = async (
  files: File[],
  companyDetails: CompanyDetails,
  onProgress?: (progress: number) => void
): Promise<Blob> => {
  // Simulate file parsing delay
  const totalSteps = files.length + 3; // parsing + merging + sorting + generating
  let completedSteps = 0;
  
  // Simulate file parsing
  for (let i = 0; i < files.length; i++) {
    await new Promise(resolve => setTimeout(resolve, 500));
    completedSteps++;
    if (onProgress) {
      onProgress(Math.floor((completedSteps / totalSteps) * 100));
    }
  }
  
  // Simulate merging
  await new Promise(resolve => setTimeout(resolve, 800));
  completedSteps++;
  if (onProgress) {
    onProgress(Math.floor((completedSteps / totalSteps) * 100));
  }
  
  // Simulate sorting
  await new Promise(resolve => setTimeout(resolve, 700));
  completedSteps++;
  if (onProgress) {
    onProgress(Math.floor((completedSteps / totalSteps) * 100));
  }
  
  // Simulate report generation
  await new Promise(resolve => setTimeout(resolve, 1000));
  completedSteps++;
  if (onProgress) {
    onProgress(100);
  }

  // In a real implementation, we would return the actual generated Word document
  // For now, return a dummy blob with some text content
  const dummyReportContent = `
    NESSUS VULNERABILITY REPORT
    
    Company: ${companyDetails.companyName}
    Date: ${companyDetails.reportDate.toLocaleDateString()}
    Prepared by: ${companyDetails.preparedBy}
    
    This is a simulated report. In the real implementation, 
    this would be a Word document (.docx) file with vulnerability data.
    
    Files processed: ${files.map(file => file.name).join(', ')}
  `;
  
  return new Blob([dummyReportContent], { type: 'text/plain' });
};
