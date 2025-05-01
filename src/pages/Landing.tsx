
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from "@/components/ui/button";
import { ArrowRight, Shield, FileText, PieChart } from "lucide-react";

const Landing = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
      {/* Hero Section */}
      <section className="pt-20 pb-16 px-4">
        <div className="container mx-auto text-center space-y-8">
          <div className="animate-fade-in">
            <h1 className="text-5xl md:text-6xl font-bold text-security-dark tracking-tight mb-6">
              Vulnerability Report Generator
            </h1>
            <p className="text-xl text-gray-600 max-w-2xl mx-auto">
              Transform your Nessus scans into professional vulnerability assessment reports with just a few clicks
            </p>
            <Button 
              onClick={() => navigate('/report')} 
              size="lg" 
              className="mt-10 bg-security-dark hover:bg-security-dark/90 text-white"
            >
              Get Started
              <ArrowRight className="ml-2" />
            </Button>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-16 bg-white">
        <div className="container mx-auto px-4">
          <h2 className="text-3xl font-bold text-center mb-12 text-security-dark">Why Choose Our Tool</h2>
          
          <div className="grid md:grid-cols-3 gap-10">
            <div className="flex flex-col items-center text-center p-6 rounded-lg hover:shadow-md transition-shadow">
              <div className="bg-security-light rounded-full p-3 mb-5">
                <FileText className="h-8 w-8 text-security-dark" />
              </div>
              <h3 className="text-xl font-semibold mb-3">Easy to Use</h3>
              <p className="text-gray-600">Simply upload your Nessus files, enter company details, and download your professional report</p>
            </div>
            
            <div className="flex flex-col items-center text-center p-6 rounded-lg hover:shadow-md transition-shadow">
              <div className="bg-security-light rounded-full p-3 mb-5">
                <Shield className="h-8 w-8 text-security-dark" />
              </div>
              <h3 className="text-xl font-semibold mb-3">Secure Processing</h3>
              <p className="text-gray-600">All file processing happens in your browser - no data ever leaves your device</p>
            </div>
            
            <div className="flex flex-col items-center text-center p-6 rounded-lg hover:shadow-md transition-shadow">
              <div className="bg-security-light rounded-full p-3 mb-5">
                <PieChart className="h-8 w-8 text-security-dark" />
              </div>
              <h3 className="text-xl font-semibold mb-3">Customizable Templates</h3>
              <p className="text-gray-600">Choose from multiple report templates to suit your specific needs</p>
            </div>
          </div>
        </div>
      </section>

      {/* Templates Section */}
      <section className="py-16 px-4">
        <div className="container mx-auto">
          <h2 className="text-3xl font-bold text-center mb-12 text-security-dark">Choose Your Template</h2>
          
          <div className="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            <div className="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow">
              <h3 className="text-lg font-semibold mb-3">Simple Template</h3>
              <p className="text-gray-600 mb-5">Clean and straightforward layout for basic reporting needs</p>
              <Button 
                variant="outline" 
                onClick={() => navigate('/report')}
                className="w-full"
              >
                Select
              </Button>
            </div>
            
            <div className="bg-white rounded-lg shadow-md p-6 border-2 border-primary hover:shadow-lg transition-shadow">
              <div className="absolute -top-3 -right-3 bg-primary text-white text-xs px-2 py-1 rounded-full">Popular</div>
              <h3 className="text-lg font-semibold mb-3">Professional Template</h3>
              <p className="text-gray-600 mb-5">Comprehensive template with detailed sections and analysis</p>
              <Button 
                onClick={() => navigate('/report')}
                className="w-full"
              >
                Select
              </Button>
            </div>
            
            <div className="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow">
              <h3 className="text-lg font-semibold mb-3">Executive Template</h3>
              <p className="text-gray-600 mb-5">Executive-focused template with summary and key findings</p>
              <Button 
                variant="outline" 
                onClick={() => navigate('/report')}
                className="w-full"
              >
                Select
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-security-dark text-white py-8">
        <div className="container mx-auto px-4 text-center">
          <p className="text-sm">Nessus Report Aggregator & Analyzer</p>
          <p className="text-xs mt-2 text-gray-400">© {new Date().getFullYear()} Vulnerability Report Tool</p>
        </div>
      </footer>
    </div>
  );
};

export default Landing;
