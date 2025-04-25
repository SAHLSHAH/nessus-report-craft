
import React from 'react';
import { Loader2 } from 'lucide-react';

interface ReportGeneratingProps {
  progress?: number;
}

const ReportGenerating: React.FC<ReportGeneratingProps> = ({ progress }) => {
  return (
    <div className="flex flex-col items-center justify-center py-10 space-y-4 animate-fade-in">
      <Loader2 className="h-12 w-12 text-security-teal animate-spin" />
      <div className="text-center">
        <h3 className="text-lg font-semibold mb-1">Generating Your Report</h3>
        <p className="text-sm text-gray-500">This may take a moment...</p>
      </div>
      
      {progress !== undefined && (
        <div className="w-full max-w-md mt-4">
          <div className="h-2 w-full bg-gray-200 rounded-full overflow-hidden">
            <div 
              className="h-full bg-security-teal" 
              style={{ width: `${progress}%` }}
            ></div>
          </div>
          <p className="text-xs text-center mt-1 text-gray-500">{progress}% Complete</p>
        </div>
      )}
    </div>
  );
};

export default ReportGenerating;
