'use client';

import React from 'react';
import { usePDF } from '@react-pdf/renderer';
import { FileText, Loader2 } from 'lucide-react';
import { PDFReport } from '@/components/PDFReport';
import { Scan, Vulnerability } from '@/lib/matrix_api';
import { useMemo } from 'react';

interface ScanPDFExportButtonProps {
    scan: Scan;
    findings: Vulnerability[];
}

const ScanPDFExportButton: React.FC<ScanPDFExportButtonProps> = ({ scan, findings }) => {
    const document = useMemo(() => <PDFReport scan={scan} findings={findings} />, [scan, findings]);
    const [instance, updateInstance] = usePDF({ document });

    if (instance.loading) {
        return (
            <button className="btn-primary rounded-xl flex items-center gap-2 shadow-lg opacity-70 cursor-wait">
                <Loader2 className="w-4 h-4 animate-spin" />
                Generating...
            </button>
        );
    }

    if (instance.error) {
        return (
            <button className="px-5 py-2.5 bg-red-50 text-red-600 rounded-xl text-sm font-bold border border-red-200 flex items-center gap-2 cursor-not-allowed" disabled>
                Error generating PDF
            </button>
        );
    }

    return (
        <a
            href={instance.url || '#'}
            download={`Matrix_Report_${scan.id}.pdf`}
            className="btn-primary rounded-xl flex items-center gap-2 shadow-lg hover:no-underline"
        >
            <FileText className="w-4 h-4" />
            Export PDF
        </a>
    );
};

export default ScanPDFExportButton;
