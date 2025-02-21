# logs.py
import customtkinter as ctk
from tkinter import filedialog
from logger import Logger
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from datetime import datetime
import re

class LogsTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.logger = Logger()
        self.setup_ui()
        
    def setup_ui(self):
        # Logs text area
        self.logs_text = ctk.CTkTextbox(self, height=400)
        self.logs_text.pack(pady=20, padx=20, fill="both", expand=True)
        
        # Button frame
        self.button_frame = ctk.CTkFrame(self)
        self.button_frame.pack(pady=10, padx=20, fill="x")
        
        # Refresh button
        self.refresh_btn = ctk.CTkButton(
            self.button_frame,
            text="Refresh Logs",
            command=self.refresh_logs
        )
        self.refresh_btn.pack(side="left", padx=5)
        
        # Export button
        self.export_btn = ctk.CTkButton(
            self.button_frame,
            text="Export Logs",
            command=self.export_logs
        )
        self.export_btn.pack(side="left", padx=5)
        
        # Generate Report button
        self.report_btn = ctk.CTkButton(
            self.button_frame,
            text="Generate Report",
            command=self.generate_report
        )
        self.report_btn.pack(side="left", padx=5)
        
        # Initial load of logs
        self.refresh_logs()
    
    def parse_logs(self):
        """Parse logs to extract relevant information for the report"""
        logs_text = self.logs_text.get("1.0", "end")
        scan_results = []
        current_scan = None
        
        # Enhanced patterns for better log matching
        detection_pattern = r"(?:⚠️ ADWARE DETECTED in|Adware detected in) (.+?)(?:\n|$)"
        rule_pattern = r"Rule: (.+?)(?:\n|$)"
        severity_pattern = r"Severity: (.+?)(?:\n|$)"
        description_pattern = r"Description: (.+?)(?:\n|$)"
        quarantine_pattern = r"(?:File quarantined:|Quarantined file:) (.+?)(?:\n|$)"
        
        for line in logs_text.split('\n'):
            # Check for detection
            detection_match = re.search(detection_pattern, line)
            if detection_match:
                if current_scan:
                    scan_results.append(current_scan)
                current_scan = {
                    'file_path': detection_match.group(1).strip(),
                    'detection_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'quarantined': False,
                    'rules_matched': [],
                    'severities': [],
                    'descriptions': []
                }
                continue
            
            # Only process these if we have a current scan
            if current_scan:
                # Check for rule matches
                rule_match = re.search(rule_pattern, line)
                if rule_match:
                    current_scan['rules_matched'].append(rule_match.group(1).strip())
                    continue
                
                # Check for severity
                severity_match = re.search(severity_pattern, line)
                if severity_match:
                    current_scan['severities'].append(severity_match.group(1).strip())
                    continue
                
                # Check for description
                description_match = re.search(description_pattern, line)
                if description_match:
                    current_scan['descriptions'].append(description_match.group(1).strip())
                    continue
                
                # Check for quarantine status
                quarantine_match = re.search(quarantine_pattern, line)
                if quarantine_match:
                    current_scan['quarantined'] = True
                    continue
        
        # Add the last scan if exists
        if current_scan:
            scan_results.append(current_scan)
        
        return scan_results
    
    def generate_report(self):
        """Generate a PDF report from the logs"""
        # Ask user where to save the report
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
            initialfile=f"adware_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
        
        if not file_path:
            return
            
        # Parse logs
        scan_results = self.parse_logs()
        
        # Create PDF
        doc = SimpleDocTemplate(file_path, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        
        # Add title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        )
        elements.append(Paragraph("Adware Detection Report", title_style))
        elements.append(Spacer(1, 20))
        
        # Add timestamp
        elements.append(Paragraph(
            f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles['Normal']
        ))
        elements.append(Spacer(1, 20))
        
        # Summary section
        elements.append(Paragraph("Summary", styles['Heading2']))
        elements.append(Spacer(1, 10))
        
        total_detections = len(scan_results)
        quarantined_files = sum(1 for result in scan_results if result['quarantined'])
        
        # Add note if no detections
        if total_detections == 0:
            elements.append(Paragraph(
                "No adware detections found in the current logs. This could mean either:",
                styles['Normal']
            ))
            elements.append(Spacer(1, 10))
            bullet_style = ParagraphStyle(
                'Bullet',
                parent=styles['Normal'],
                leftIndent=20,
                firstLineIndent=0,
                spaceBefore=0,
                spaceAfter=5
            )
            elements.append(Paragraph("• No malicious files were detected during the scan", bullet_style))
            elements.append(Paragraph("• No scans have been performed yet", bullet_style))
            elements.append(Paragraph("• The logs have been cleared", bullet_style))
            elements.append(Spacer(1, 10))
        
        summary_data = [
            ["Total Detections", str(total_detections)],
            ["Quarantined Files", str(quarantined_files)],
            ["Files Pending Action", str(total_detections - quarantined_files)]
        ]
        
        summary_table = Table(summary_data, colWidths=[200, 100])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 20))
        
        # Detailed findings section
        if scan_results:
            elements.append(Paragraph("Detailed Findings", styles['Heading2']))
            elements.append(Spacer(1, 10))
            
            # Sort scan results: quarantined files first, then pending files
            quarantined_results = [result for result in scan_results if result['quarantined']]
            pending_results = [result for result in scan_results if not result['quarantined']]
            
            # Sort each list alphabetically by file path
            quarantined_results.sort(key=lambda x: x['file_path'].lower())
            pending_results.sort(key=lambda x: x['file_path'].lower())
            
            # Create sections for quarantined and pending files
            bullet_style = ParagraphStyle(
                'Bullet',
                parent=styles['Normal'],
                leftIndent=20,
                firstLineIndent=0,
                spaceBefore=5,
                spaceAfter=5
            )
            
            # Quarantined Files Section
            if quarantined_results:
                elements.append(Paragraph("Quarantined Files:", styles['Heading3']))
                for result in quarantined_results:
                    elements.append(Paragraph(
                        f"• File: {result['file_path']}", 
                        bullet_style
                    ))
                    elements.append(Paragraph(
                        f"  Detection Time: {result['detection_time']}", 
                        bullet_style
                    ))
                    
                    # Add rules information if available
                    if result['rules_matched']:
                        for i, rule in enumerate(result['rules_matched']):
                            severity = result['severities'][i] if i < len(result['severities']) else 'Unknown'
                            description = result['descriptions'][i] if i < len(result['descriptions']) else 'No description available'
                            elements.append(Paragraph(f"  - Rule: {rule}", bullet_style))
                            elements.append(Paragraph(f"    Severity: {severity}", bullet_style))
                            elements.append(Paragraph(f"    Description: {description}", bullet_style))
                    
                elements.append(Spacer(1, 10))
            
            # Pending Files Section
            if pending_results:
                elements.append(Paragraph("Files Pending Action:", styles['Heading3']))
                for result in pending_results:
                    elements.append(Paragraph(
                        f"• File: {result['file_path']}", 
                        bullet_style
                    ))
                    elements.append(Paragraph(
                        f"  Detection Time: {result['detection_time']}", 
                        bullet_style
                    ))
                    
                    # Add rules information if available
                    if result['rules_matched']:
                        for i, rule in enumerate(result['rules_matched']):
                            severity = result['severities'][i] if i < len(result['severities']) else 'Unknown'
                            description = result['descriptions'][i] if i < len(result['descriptions']) else 'No description available'
                            elements.append(Paragraph(f"  - Rule: {rule}", bullet_style))
                            elements.append(Paragraph(f"    Severity: {severity}", bullet_style))
                            elements.append(Paragraph(f"    Description: {description}", bullet_style))
        
        # Generate PDF
        try:
            doc.build(elements)
            self.logger.log(f"PDF report generated: {file_path}")
            
            # Show success in logs
            self.logs_text.insert("end", f"\nPDF report generated successfully: {file_path}\n")
            self.logs_text.see("end")
        except Exception as e:
            self.logger.log(f"Error generating PDF report: {str(e)}")
            self.logs_text.insert("end", f"\nError generating PDF report: {str(e)}\n")
            self.logs_text.see("end")
    
    def refresh_logs(self):
        self.logs_text.delete("1.0", "end")
        logs = self.logger.get_logs()
        for log in logs:
            self.logs_text.insert("end", f"{log}\n")
            
    def export_logs(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            with open(file_path, 'w') as f:
                f.write(self.logs_text.get("1.0", "end"))
            self.logger.log(f"Logs exported to: {file_path}")