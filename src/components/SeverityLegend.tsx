
import React from 'react';

const SeverityLegend: React.FC = () => {
  const severities = [
    { name: 'Critical', color: 'severity-critical' },
    { name: 'High', color: 'severity-high' },
    { name: 'Medium', color: 'severity-medium' },
    { name: 'Low', color: 'severity-low' },
    { name: 'Info', color: 'severity-info' },
  ];

  return (
    <div className="flex flex-wrap gap-3 justify-center md:justify-start">
      {severities.map((severity) => (
        <div key={severity.name} className="flex items-center">
          <div className={`h-3 w-3 rounded-full ${severity.color.replace('text-', 'bg-')}`}></div>
          <span className="ml-1 text-xs">{severity.name}</span>
        </div>
      ))}
    </div>
  );
};

export default SeverityLegend;
