
import React, { useState, useRef } from 'react';
import { FileUp, X, Check, AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { useToast } from '@/components/ui/use-toast';

interface FileUploadProps {
  onFilesUploaded: (files: File[]) => void;
  acceptedFileTypes?: string[];
  maxFiles?: number;
}

const FileUpload: React.FC<FileUploadProps> = ({
  onFilesUploaded,
  acceptedFileTypes = ['.nessus', '.xml'],
  maxFiles = 50,
}) => {
  const [files, setFiles] = useState<File[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();

  const handleDragEnter = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const validateFiles = (fileList: File[]): File[] => {
    return fileList.filter(file => {
      const fileExtension = '.' + file.name.split('.').pop()?.toLowerCase();
      if (!acceptedFileTypes.includes(fileExtension)) {
        toast({
          title: "Invalid file type",
          description: `${file.name} is not a valid Nessus file (.nessus or .xml)`,
          variant: "destructive"
        });
        return false;
      }
      return true;
    });
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const droppedFiles = Array.from(e.dataTransfer.files);
      handleFileSelection(droppedFiles);
    }
  };

  const handleFileSelection = (selectedFiles: File[]) => {
    const validFiles = validateFiles(selectedFiles);
    
    if (files.length + validFiles.length > maxFiles) {
      toast({
        title: "Too many files",
        description: `You can only upload up to ${maxFiles} files at once.`,
        variant: "destructive"
      });
      return;
    }
    
    if (validFiles.length > 0) {
      const newFiles = [...files, ...validFiles];
      setFiles(newFiles);
      onFilesUploaded(newFiles);
      toast({
        title: "Files added",
        description: `${validFiles.length} file(s) have been added successfully.`,
      });
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const selectedFiles = Array.from(e.target.files);
      handleFileSelection(selectedFiles);
    }
  };

  const removeFile = (indexToRemove: number) => {
    const newFiles = files.filter((_, index) => index !== indexToRemove);
    setFiles(newFiles);
    onFilesUploaded(newFiles);
  };

  const openFileDialog = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  return (
    <div className="space-y-4 w-full">
      <div
        className={cn(
          "border-2 border-dashed rounded-lg p-10 text-center cursor-pointer transition-all duration-200",
          isDragging ? "border-security-teal bg-blue-50" : "border-gray-300 hover:border-security-teal",
          "flex flex-col items-center justify-center h-48"
        )}
        onDragEnter={handleDragEnter}
        onDragLeave={handleDragLeave}
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        onClick={openFileDialog}
      >
        <input 
          type="file" 
          ref={fileInputRef}
          className="hidden" 
          multiple
          accept={acceptedFileTypes.join(',')}
          onChange={handleFileInputChange}
        />
        <FileUp className="h-12 w-12 mb-4 text-security-dark" />
        <h3 className="text-lg font-semibold mb-2">Drag & Drop Nessus Files</h3>
        <p className="text-sm text-gray-500 mb-3">
          or <span className="text-security-teal font-medium">browse</span> to upload
        </p>
        <p className="text-xs text-gray-400">Supported file types: .nessus, .xml</p>
      </div>

      {files.length > 0 && (
        <div className="bg-white rounded-lg shadow p-4 animate-fade-in">
          <div className="flex justify-between items-center mb-3">
            <h3 className="font-medium flex items-center">
              <Check className="h-4 w-4 text-security-teal mr-2" />
              {files.length} file{files.length !== 1 ? 's' : ''} uploaded
            </h3>
            <Button 
              variant="ghost" 
              size="sm"
              className="text-xs text-gray-500 hover:text-red-500"
              onClick={() => {
                setFiles([]);
                onFilesUploaded([]);
              }}
            >
              Remove all
            </Button>
          </div>

          <div className="max-h-40 overflow-y-auto pr-2">
            {files.map((file, index) => (
              <div 
                key={`${file.name}-${index}`} 
                className="flex justify-between items-center p-2 border-b last:border-0"
              >
                <div className="flex items-center">
                  <span className="text-sm truncate max-w-[300px]">{file.name}</span>
                  <span className="text-xs text-gray-400 ml-2">
                    ({(file.size / 1024).toFixed(1)} KB)
                  </span>
                </div>
                <Button 
                  variant="ghost"
                  size="sm"
                  className="text-gray-400 hover:text-red-500 h-6 w-6 p-0"
                  onClick={(e) => {
                    e.stopPropagation();
                    removeFile(index);
                  }}
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>
            ))}
          </div>

          {files.length > 10 && (
            <div className="mt-2 flex items-center text-xs text-amber-600 border-l-2 border-amber-500 pl-2 bg-amber-50 p-1 rounded">
              <AlertTriangle className="h-3 w-3 mr-1" />
              Large number of files may take longer to process
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default FileUpload;
