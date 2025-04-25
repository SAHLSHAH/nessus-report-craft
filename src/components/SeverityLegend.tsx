
import React from 'react';

const SeverityLegend: React.FC = () => {
  const severities = [
    { name: 'Critical', color: 'bg-security-critical' },
    { name: 'High', color: 'bg-security-high' },
    { name: 'Medium', color: 'bg-security-medium' },
    { name: 'Low', color: 'bg-security-low' },
    { name: 'Info', color: 'bg-security-info' },
  ];

  return (
    <div className="flex flex-wrap gap-3 justify-center md:justify-start">
      {severities.map((severity) => (
        <div key={severity.name} className="flex items-center" aria-label={`${severity.name} severity`}>
          <div className={`h-3 w-3 rounded-full ${severity.color}`}></div>
          <span className="ml-1 text-xs">{severity.name}</span>
        </div>
      ))}
    </div>
  );
};

export default SeverityLegend;
