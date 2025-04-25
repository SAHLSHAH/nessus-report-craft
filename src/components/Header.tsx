
import React from 'react';
import { AlertTriangle } from 'lucide-react';

const Header: React.FC = () => {
  return (
    <header className="bg-security-dark text-white p-4 md:p-6">
      <div className="container mx-auto">
        <div className="flex flex-col md:flex-row md:items-center justify-between space-y-4 md:space-y-0">
          <div>
            <h1 className="text-2xl md:text-3xl font-bold">Nessus Report Aggregator</h1>
            <p className="text-security-light/80 text-sm md:text-base">
              Upload, merge, and analyze Nessus vulnerability reports
            </p>
          </div>
          
          <div className="bg-amber-600/20 border border-amber-600/30 rounded-md px-3 py-2 flex items-start md:items-center text-xs md:text-sm text-amber-100 max-w-md">
            <AlertTriangle className="h-4 w-4 flex-shrink-0 mr-2 mt-0.5 md:mt-0" />
            <span>
              This tool processes files locally in your browser. No data is transmitted to remote servers.
            </span>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
