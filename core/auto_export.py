"""
Auto Export Module
扫描结果自动导出模块

功能:
- 扫描完成后自动生成报告
- 支持多种格式 (HTML, PDF, CSV, JSON)
- 导出配置管理
"""

import os
import logging
from typing import Optional, Dict, Any
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class AutoExportConfig:
    """自动导出配置"""
    
    def __init__(self):
        self.enabled: bool = True
        self.formats: list = ['html', 'json']
        self.output_dir: str = './results'
        self.auto_export_on_complete: bool = True
        self.include_raw_data: bool = True
        self.report_template: Optional[str] = None


class AutoExporter:
    """
    扫描结果自动导出器
    
    功能:
    - 扫描完成时自动生成报告
    - 支持多种导出格式
    - 可配置的导出选项
    """

    def __init__(self, config: Optional[AutoExportConfig] = None):
        self.config = config or AutoExportConfig()
        os.makedirs(self.config.output_dir, exist_ok=True)

    def on_scan_complete(self, task_id: str, result: Any) -> Dict[str, str]:
        """
        扫描完成时的回调
        
        生成所有配置的报告格式
        """
        if not self.config.enabled:
            logger.info("Auto-export is disabled")
            return {}
        
        if not self.config.auto_export_on_complete:
            logger.info("Auto-export on complete is disabled")
            return {}
        
        exported_files = {}
        
        for fmt in self.config.formats:
            try:
                file_path = self._export(task_id, result, fmt)
                if file_path:
                    exported_files[fmt] = file_path
                    logger.info(f"Auto-exported {fmt} report: {file_path}")
            except Exception as e:
                logger.error(f"Failed to export {fmt} report: {e}")
        
        return exported_files

    def _export(self, task_id: str, result: Any, format: str) -> Optional[str]:
        """根据格式导出报告"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_name = f"{task_id}_{timestamp}"
        
        data = result.to_dict() if hasattr(result, 'to_dict') else result
        output_dir = os.path.join(self.config.output_dir, task_id)
        os.makedirs(output_dir, exist_ok=True)
        
        if format == 'html':
            return self._export_html(base_name, data, output_dir)
        elif format == 'json':
            return self._export_json(base_name, data, output_dir)
        elif format == 'csv':
            return self._export_csv(base_name, data, output_dir)
        elif format == 'pdf':
            return self._export_pdf(base_name, data, output_dir)
        else:
            logger.warning(f"Unsupported export format: {format}")
            return None

    def _export_html(self, base_name: str, data: Dict, output_dir: str) -> str:
        """导出HTML报告"""
        from ..exporters.enhanced_html_reporter import EnhancedHtmlReporter
        
        output_path = os.path.join(output_dir, f"{base_name}.html")
        reporter = EnhancedHtmlReporter()
        reporter.export(data, output_path)
        return output_path

    def _export_json(self, base_name: str, data: Dict, output_dir: str) -> str:
        """导出JSON报告"""
        output_path = os.path.join(output_dir, f"{base_name}.json")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return output_path

    def _export_csv(self, base_name: str, data: Dict, output_dir: str) -> str:
        """导出CSV报告"""
        import csv
        
        output_path = os.path.join(output_dir, f"{base_name}.csv")
        vulns = data.get('vulnerabilities', [])
        
        if not vulns:
            return output_path
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            if vulns:
                writer = csv.DictWriter(f, fieldnames=vulns[0].keys())
                writer.writeheader()
                writer.writerows(vulns)
        
        return output_path

    def _export_pdf(self, base_name: str, data: Dict, output_dir: str) -> str:
        """导出PDF报告"""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
            from reportlab.lib.styles import getSampleStyleSheet
        except ImportError:
            logger.warning("reportlab not installed, PDF export skipped")
            return None
        
        output_path = os.path.join(output_dir, f"{base_name}.pdf")
        
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        story.append(Paragraph("ApiRed Security Scan Report", styles['Title']))
        story.append(Spacer(1, 12))
        
        summary = data.get('summary', {})
        story.append(Paragraph(f"Target: {data.get('target', 'N/A')}", styles['Normal']))
        story.append(Paragraph(f"Scan Date: {data.get('timestamp', 'N/A')}", styles['Normal']))
        story.append(Paragraph(f"Total APIs: {summary.get('total_apis', 0)}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        vulns = data.get('vulnerabilities', [])
        if vulns:
            story.append(Paragraph("Vulnerabilities Found:", styles['Heading2']))
            for vuln in vulns[:50]:
                story.append(Paragraph(
                    f"- [{vuln.get('severity', '?').upper()}] {vuln.get('type', 'Unknown')}: {vuln.get('path', 'N/A')}",
                    styles['Normal']
                ))
        
        doc.build(story)
        return output_path


_global_exporter: Optional[AutoExporter] = None


def get_auto_exporter() -> AutoExporter:
    """获取全局自动导出器"""
    global _global_exporter
    if _global_exporter is None:
        _global_exporter = AutoExporter()
    return _global_exporter


def configure_auto_export(
    enabled: bool = True,
    formats: Optional[list] = None,
    output_dir: str = './results'
):
    """配置自动导出"""
    exporter = get_auto_exporter()
    exporter.config.enabled = enabled
    if formats:
        exporter.config.formats = formats
    exporter.config.output_dir = output_dir
