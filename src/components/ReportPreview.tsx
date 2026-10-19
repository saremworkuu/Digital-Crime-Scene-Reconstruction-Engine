import React from 'react';
import { ForensicReport } from '../types';
import { Printer, Download } from 'lucide-react';

interface ReportPreviewProps {
  report: ForensicReport;
  onPrint?: () => void;
  onDownloadHtml?: () => void;
}

export const ReportPreview: React.FC<ReportPreviewProps> = ({ 
  report, 
  onPrint, 
  onDownloadHtml 
}) => {
  const inventory = report.evidenceInventory || report.evidence_inventory || [];

  return (
    <div className="bg-[#161413]/90 border border-[#2b2523] rounded-2xl p-6 space-y-6 backdrop-blur-xl shadow-xl">
      <div className="flex items-center justify-between pb-4 border-b border-[#282321]">
        <div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#2a140d] text-[#f95721] border border-[#ea580c]/30 font-semibold">
            {report.classification || 'TLP:AMBER'}
          </span>
          <h2 className="text-base font-bold text-[#fafaf9] mt-2">{report.caseName || report.case_name}</h2>
          <p className="text-xs text-[#a8a29e]">Examiner: {report.generatorName || report.generator_name} ({report.generatorRole || report.generator_role})</p>
        </div>
        <div className="flex items-center gap-2">
          {onPrint && (
            <button
              onClick={onPrint}
              className="px-3 py-1.5 rounded-lg bg-[#241e1b] hover:bg-[#342a26] text-[#e7e5e4] text-xs font-medium flex items-center gap-1.5 transition-colors border border-[#38312d] cursor-pointer"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / PDF</span>
            </button>
          )}
          {onDownloadHtml && (
            <button
              onClick={onDownloadHtml}
              className="px-3.5 py-1.5 rounded-lg bg-[#f95721] hover:bg-[#ea580c] text-white text-xs font-semibold flex items-center gap-1.5 transition-all shadow-[0_0_12px_rgba(249,87,33,0.3)] cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export HTML</span>
            </button>
          )}
        </div>
      </div>

      <div className="space-y-2">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-[#a8a29e] font-mono">1. Executive Summary</h3>
        <p className="text-xs text-[#d6d3d1] leading-relaxed bg-[#100f0e] p-4 rounded-xl border border-[#282321]">
          {report.executiveSummary || report.executive_summary}
        </p>
      </div>

      <div className="space-y-2">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-[#a8a29e] font-mono">2. Evidence Chain of Custody</h3>
        <div className="border border-[#282321] rounded-xl overflow-hidden">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#100f0e] text-[#a8a29e] border-b border-[#282321] font-mono text-[11px]">
              <tr>
                <th className="p-2.5">File Name</th>
                <th className="p-2.5">SHA-256 Hash</th>
                <th className="p-2.5 text-right">Events Extracted</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#282321] text-[#d6d3d1]">
              {inventory.map((item: any, i: number) => (
                <tr key={i} className="hover:bg-[#1a1716] font-mono text-xs">
                  <td className="p-2.5">{item.filename}</td>
                  <td className="p-2.5 text-[#f95721] text-[11px] truncate max-w-xs">{item.sha256Hash || item.sha256_hash}</td>
                  <td className="p-2.5 text-right font-mono">{(item.eventsExtracted || item.events_extracted || 0).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
