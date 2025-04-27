import React, { useState } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { useToast } from '@/components/ui/use-toast';
import { Button } from '@/components/ui/button';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';

import Header from '@/components/Header';
import FileUpload from '@/components/FileUpload';
import CompanyDetailsForm, { CompanyDetails } from '@/components/CompanyDetailsForm';
import SeverityLegend from '@/components/SeverityLegend';
import EmptyState from '@/components/EmptyState';
import ReportGenerating from '@/components/ReportGenerating';
import ReportSuccess from '@/components/ReportSuccess';
import { generateReport } from '@/services/reportService';

type AppState = 'idle' | 'generating' | 'success' | 'error';

const Index = () => {
  const navigate = useNavigate();
  const [files, setFiles] = useState<File[]>([]);
  const [appState, setAppState] = useState<AppState>('idle');
  const [reportBlob, setReportBlob] = useState<Blob | null>(null);
  const [progress, setProgress] = useState<number>(0);
  const { toast } = useToast();

  const handleFilesUploaded = (uploadedFiles: File[]) => {
    setFiles(uploadedFiles);
    if (appState === 'success') {
      setAppState('idle');
    }
  };

  const handleFormSubmit = async (companyDetails: CompanyDetails) => {
    if (files.length === 0) {
      toast({
        title: "No files uploaded",
        description: "Please upload at least one Nessus file before generating a report.",
        variant: "destructive",
      });
      return;
    }

    try {
      setAppState('generating');
      setProgress(0);
      
      const blob = await generateReport(files, companyDetails, (progressValue) => {
        setProgress(progressValue);
      });
      
      setReportBlob(blob);
      setAppState('success');
    } catch (error) {
      console.error("Error generating report:", error);
      toast({
        title: "Error generating report",
        description: "An error occurred while generating the report. Please try again.",
        variant: "destructive",
      });
      setAppState('error');
    }
  };

  const handleDownloadReport = () => {
    if (!reportBlob) return;
    
    const url = URL.createObjectURL(reportBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `Vulnerability_Report_${new Date().toISOString().split('T')[0]}.docx`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    toast({
      title: "Report downloaded",
      description: "Your vulnerability report has been downloaded successfully.",
    });
  };

  const handleReset = () => {
    setAppState('idle');
    setReportBlob(null);
    setFiles([]);
  };

  return (
    <div className="min-h-screen flex flex-col bg-gray-50">
      <Header />
      
      <main className="container mx-auto py-8 px-4 flex-grow">
        <Button 
          variant="outline" 
          onClick={() => navigate('/')} 
          className="mb-6"
        >
          <ArrowLeft className="mr-2" />
          Back to Home
        </Button>

        <div className="grid md:grid-cols-3 gap-8">
          <div className="md:col-span-2">
            <Card>
              <CardContent className="p-6">
                <h2 className="text-xl font-semibold mb-4">Upload Nessus Files</h2>
                <FileUpload onFilesUploaded={handleFilesUploaded} />
              </CardContent>
            </Card>
          </div>

          <div>
            <Card>
              <CardContent className="p-6">
                <h2 className="text-xl font-semibold mb-4">Report Details</h2>
                <CompanyDetailsForm 
                  onSubmit={handleFormSubmit}
                  isDisabled={appState === 'generating'}
                />
                <Separator className="my-4" />
                <div>
                  <h3 className="text-sm font-medium mb-2">Severity Legend</h3>
                  <SeverityLegend />
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        <div className="mt-8">
          <Card className="shadow-md">
            <CardContent className="p-6">
              {files.length === 0 && appState === 'idle' && (
                <EmptyState />
              )}
              
              {appState === 'generating' && (
                <ReportGenerating progress={progress} />
              )}
              
              {appState === 'success' && (
                <ReportSuccess 
                  onDownload={handleDownloadReport} 
                  onReset={handleReset} 
                />
              )}
            </CardContent>
          </Card>
        </div>
      </main>
      
      <footer className="bg-gray-100 border-t py-4">
        <div className="container mx-auto px-4 text-center text-sm text-gray-500">
          <p>Nessus Report Aggregator & Analyzer</p>
          <p className="text-xs mt-1">© {new Date().getFullYear()} Vulnerability Report Tool</p>
        </div>
      </footer>
    </div>
  );
};

export default Index;
