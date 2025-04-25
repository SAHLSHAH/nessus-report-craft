
import React from 'react';
import { Check, Download } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface ReportSuccessProps {
  onDownload: () => void;
  onReset: () => void;
}

const ReportSuccess: React.FC<ReportSuccessProps> = ({ onDownload, onReset }) => {
  return (
    <div className="flex flex-col items-center justify-center py-10 space-y-6 animate-fade-in">
      <div className="rounded-full bg-green-100 p-3">
        <Check className="h-10 w-10 text-green-600" />
      </div>
      
      <div className="text-center">
        <h3 className="text-xl font-semibold mb-2">Report Generated Successfully!</h3>
        <p className="text-gray-500">Your vulnerability report has been created and is ready for download.</p>
      </div>
      
      <div className="flex flex-col md:flex-row gap-3 w-full max-w-md">
        <Button 
          onClick={onDownload} 
          className="bg-security-dark hover:bg-security-dark/90 text-white flex-1"
        >
          <Download className="mr-2 h-4 w-4" /> Download Report
        </Button>
        <Button 
          variant="outline" 
          onClick={onReset}
          className="flex-1"
        >
          Create Another Report
        </Button>
      </div>
    </div>
  );
};

export default ReportSuccess;
