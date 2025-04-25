
import React from 'react';
import { FileText } from 'lucide-react';

const EmptyState: React.FC = () => {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="bg-gray-100 p-6 rounded-full mb-4">
        <FileText className="h-10 w-10 text-security-dark/70" />
      </div>
      <h3 className="text-xl font-semibold mb-2">No Nessus Files Uploaded</h3>
      <p className="text-gray-500 max-w-md">
        Upload Nessus scan files (.nessus or .xml) to merge and generate a comprehensive vulnerability report.
      </p>
      <div className="mt-6 bg-blue-50 border border-blue-200 rounded-lg p-4 max-w-lg">
        <h4 className="font-medium text-sm mb-2 text-security-dark">How It Works</h4>
        <ol className="text-sm text-left space-y-2 text-gray-600">
          <li className="flex">
            <span className="bg-white rounded-full h-5 w-5 flex items-center justify-center text-xs font-bold mr-2">1</span> 
            <span>Upload one or more Nessus files</span>
          </li>
          <li className="flex">
            <span className="bg-white rounded-full h-5 w-5 flex items-center justify-center text-xs font-bold mr-2">2</span>
            <span>Fill in company details for the report header</span>
          </li>
          <li className="flex">
            <span className="bg-white rounded-full h-5 w-5 flex items-center justify-center text-xs font-bold mr-2">3</span>
            <span>Generate and download the consolidated Word report</span>
          </li>
        </ol>
      </div>
    </div>
  );
};

export default EmptyState;
