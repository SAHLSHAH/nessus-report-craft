
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from "@/components/ui/button";
import { ArrowRight } from "lucide-react";

const Landing = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
      <div className="container mx-auto px-4 py-16">
        <div className="text-center space-y-6 max-w-3xl mx-auto">
          <h1 className="text-4xl md:text-6xl font-bold text-gray-900 tracking-tight">
            Vulnerability Report Generator
          </h1>
          <p className="text-xl text-gray-600 max-w-2xl mx-auto">
            Generate professional vulnerability assessment reports from Nessus scans with customizable templates
          </p>
          <Button 
            onClick={() => navigate('/report')} 
            size="lg" 
            className="mt-8"
          >
            Get Started
            <ArrowRight className="ml-2" />
          </Button>

          <div className="mt-16 grid md:grid-cols-3 gap-8">
            <div className="p-6 bg-white rounded-lg shadow-md">
              <h3 className="text-lg font-semibold mb-2">Simple Template</h3>
              <p className="text-gray-600">Clean and straightforward layout for basic reporting needs</p>
            </div>
            <div className="p-6 bg-white rounded-lg shadow-md border-2 border-primary">
              <h3 className="text-lg font-semibold mb-2">Professional Template</h3>
              <p className="text-gray-600">Comprehensive template with detailed sections and analysis</p>
            </div>
            <div className="p-6 bg-white rounded-lg shadow-md">
              <h3 className="text-lg font-semibold mb-2">Executive Template</h3>
              <p className="text-gray-600">Executive-focused template with summary and key findings</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Landing;
