'use client';

import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { UploadCloud } from 'lucide-react';
import { api } from '@/lib/api';
import { useRouter } from 'next/navigation';

export default function FileUpload() {
  const [file, setFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles.length > 0) {
      setFile(acceptedFiles[0]);
      setError(null);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'message/rfc822': ['.eml'] },
    maxFiles: 1,
  });

  const handleUpload = async () => {
    if (!file) return;
    setIsUploading(true);
    setError(null);
    try {
      const res = await api.cases.upload(file);
      router.push(`/cases/${res.id}`);
    } catch (err: any) {
      setError(err.message || 'Upload failed');
      setIsUploading(false);
    }
  };

  return (
    <div className="w-full">
      <div 
        {...getRootProps()} 
        className={`border-2 border-dashed rounded-lg p-10 text-center cursor-pointer transition-colors ${
          isDragActive ? 'border-primary-500 bg-primary-900/20' : 'border-gray-700 bg-surface hover:bg-gray-800'
        }`}
      >
        <input {...getInputProps()} />
        <UploadCloud className="w-12 h-12 mx-auto text-gray-400 mb-4" />
        {isDragActive ? (
          <p className="text-primary-400 font-medium">Drop the .eml file here ...</p>
        ) : (
          <p className="text-gray-300">Drag & drop an .eml file here, or click to select</p>
        )}
      </div>

      {file && (
        <div className="mt-4 p-4 bg-surface border border-gray-700 rounded-lg flex items-center justify-between">
          <div>
            <p className="font-medium text-gray-200">{file.name}</p>
            <p className="text-sm text-gray-400">{(file.size / 1024).toFixed(2)} KB</p>
          </div>
          <button 
            onClick={handleUpload}
            disabled={isUploading}
            className="px-4 py-2 bg-primary-600 hover:bg-primary-500 text-white rounded font-medium disabled:opacity-50"
          >
            {isUploading ? 'Uploading...' : 'Upload & Analyze'}
          </button>
        </div>
      )}

      {error && <p className="mt-4 text-red-400 text-sm">{error}</p>}
    </div>
  );
}
