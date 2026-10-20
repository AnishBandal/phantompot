"""KPI Report Generator for Objective 4: System Effectiveness Evaluation

Generates comprehensive evaluation reports with visualizations, metrics analysis,
and recommendations for the honeypot system KPI measurements.

Usage:
    # Generate report from existing sessions log
    python scripts/generate_kpi_report.py --sessions logs/sessions.jsonl
    
    # Generate report with custom output path
    python scripts/generate_kpi_report.py --output reports/my_report.html
    
    # Generate report with evaluation results
    python scripts/generate_kpi_report.py --eval objective4_report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
SRC_DIR = BASE_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.kpi_metrics import KPIMetricsCollector
from ml.predict import predict_session_anomaly


class ObjectiveKPIReportGenerator:
    """Generate comprehensive KPI evaluation reports."""
    
    def __init__(self, output_dir: Path = None) -> None:
        self.output_dir = output_dir or Path(BASE_DIR) / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.timestamp = datetime.now()
        self.report_id = f"KPI-REPORT-{self.timestamp.strftime('%Y%m%d-%H%M%S')}"
    
    def generate_json_report(self, eval_data: Dict[str, Any], 
                            output_path: Optional[Path] = None) -> Path:
        """Generate JSON format report."""
        output_path = output_path or self.output_dir / f"{self.report_id}.json"
        
        report = {
            "report_metadata": {
                "report_id": self.report_id,
                "generated_at": self.timestamp.isoformat(),
                "objective": "Objective 4: System Effectiveness Evaluation via measurable KPIs",
            },
            "evaluation_data": eval_data,
            "report_sections": self._generate_report_sections(eval_data),
        }
        
        output_path.write_text(json.dumps(report, indent=2, default=str))
        return output_path
    
    def generate_markdown_report(self, eval_data: Dict[str, Any],
                                output_path: Optional[Path] = None) -> Path:
        """Generate Markdown format report."""
        output_path = output_path or self.output_dir / f"{self.report_id}.md"
        
        md_content = self._build_markdown_report(eval_data)
        output_path.write_text(md_content)
        return output_path
    
    def generate_html_report(self, eval_data: Dict[str, Any],
                            output_path: Optional[Path] = None) -> Path:
        """Generate HTML format report with embedded CSS and visualizations."""
        output_path = output_path or self.output_dir / f"{self.report_id}.html"
        
        html_content = self._build_html_report(eval_data)
        output_path.write_text(html_content)
        return output_path
    
    def _generate_report_sections(self, eval_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Generate analysis sections for the report."""
        sections = {}
        
        # Executive Summary
        sections["executive_summary"] = self._generate_executive_summary(eval_data)
        
        # KPI 1 Analysis
        sections["kpi_1_attack_detection"] = self._generate_detection_rate_analysis(eval_data)
        
        # KPI 2 Analysis
        sections["kpi_2_protocol_coverage"] = self._generate_protocol_coverage_analysis(eval_data)
        
        # KPI 3 Analysis
        sections["kpi_3_logging_accuracy"] = self._generate_logging_accuracy_analysis(eval_data)
        
        # KPI 4 Analysis
        sections["kpi_4_response_time"] = self._generate_response_time_analysis(eval_data)
        
        # Recommendations
        sections["recommendations"] = self._generate_recommendations(eval_data)
        
        return sections
    
    def _generate_executive_summary(self, eval_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary."""
        metadata = eval_data.get("evaluation_metadata", {})
        
        return {
            "title": "Executive Summary",
            "overview": (
                "This report documents the comprehensive evaluation of the PhantomPot "
                "multi-protocol honeypot system against four key performance indicators (KPIs)"
            ),
            "test_execution": {
                "total_scenarios": metadata.get("scenarios_run", 0),
                "successful_scenarios": metadata.get("scenarios_passed", 0),
                "failed_scenarios": metadata.get("scenarios_failed", 0),
                "success_rate": f"{metadata.get('scenario_success_rate', 0):.1f}%",
                "duration_seconds": metadata.get("total_duration_seconds", 0),
            },
            "kpi_scores": self._calculate_kpi_scores(eval_data),
        }
    
    def _calculate_kpi_scores(self, eval_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Calculate scores for each KPI."""
        scores = {}
        
        # KPI 1: Attack Detection Rate
        detection = eval_data.get("kpi_1_attack_detection_rate", {})
        detection_metrics = detection.get("metrics", {})
        attack_rate = detection_metrics.get("attack_detection_rate", 0)
        fp_rate = detection_metrics.get("false_positive_rate", 0)
        kpi1_score = (attack_rate * 0.6 + (100 - fp_rate) * 0.4) / 100 * 100
        scores["kpi_1"] = {
            "name": "Attack Detection Rate",
            "score": f"{kpi1_score:.1f}/100",
            "status": self._score_to_status(kpi1_score),
        }
        
        # KPI 2: Protocol Coverage
        coverage = eval_data.get("kpi_2_protocol_coverage", {})
        coverage_metrics = coverage.get("metrics", {})
        active_protocols = coverage_metrics.get("active_protocol_count", 0)
        kpi2_score = (active_protocols / 4) * 100
        scores["kpi_2"] = {
            "name": "Protocol Coverage",
            "score": f"{kpi2_score:.1f}/100",
            "status": self._score_to_status(kpi2_score),
        }
        
        # KPI 3: Logging Accuracy
        accuracy = eval_data.get("kpi_3_logging_accuracy", {})
        accuracy_metrics = accuracy.get("metrics", {})
        logging_acc = accuracy_metrics.get("overall_logging_accuracy_percent", 0)
        scores["kpi_3"] = {
            "name": "Logging Accuracy",
            "score": f"{logging_acc:.1f}/100",
            "status": self._score_to_status(logging_acc),
        }
        
        # KPI 4: Response Time (inversely correlated - lower is better)
        response_time = eval_data.get("kpi_4_system_response_time", {})
        response_metrics = response_time.get("metrics", {})
        avg_ms = response_metrics.get("average_ms", 0)
        # Score: Good if < 10ms (100), acceptable if < 100ms (50), poor if >= 100ms (0)
        if avg_ms <= 10:
            kpi4_score = 100
        elif avg_ms <= 100:
            kpi4_score = 50 + (100 - avg_ms) * 0.5
        else:
            kpi4_score = max(0, 100 - (avg_ms - 100) / 10)
        scores["kpi_4"] = {
            "name": "Response Time",
            "score": f"{kpi4_score:.1f}/100",
            "status": self._score_to_status(kpi4_score),
        }
        
        # Overall Score
        overall = (kpi1_score + kpi2_score + kpi3_score + kpi4_score) / 4
        scores["overall"] = {
            "name": "Overall System Effectiveness",
            "score": f"{overall:.1f}/100",
            "status": self._score_to_status(overall),
        }
        
        return scores
    
    def _score_to_status(self, score: float) -> str:
        """Convert numerical score to status."""
        if score >= 90:
            return "EXCELLENT"
        elif score >= 80:
            return "GOOD"
        elif score >= 70:
            return "ACCEPTABLE"
        elif score >= 60:
            return "NEEDS IMPROVEMENT"
        else:
            return "CRITICAL"
    
    def _generate_detection_rate_analysis(self, eval_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate KPI 1 analysis."""
        detection = eval_data.get("kpi_1_attack_detection_rate", {})
        metrics = detection.get("metrics", {})
        interpretation = detection.get("interpretation", {})
        
        return {
            "title": "KPI 1: Attack Detection Rate",
            "description": "ML model's ability to detect attacks (TP/FP classification rates)",
            "metrics": metrics,
            "key_findings": [
                f"Attack Detection Rate: {metrics.get('attack_detection_rate', 0):.1f}%",
                f"True Positive Rate: {metrics.get('true_positive_rate', 0):.1f}%",
                f"False Positive Rate: {metrics.get('false_positive_rate', 0):.1f}%",
                f"Precision: {metrics.get('precision', 0):.1f}%",
                f"F1 Score: {metrics.get('f1_score', 0):.1f}%",
            ],
            "interpretation": interpretation,
            "recommendations": self._get_detection_recommendations(metrics),
        }
    
    def _generate_protocol_coverage_analysis(self, eval_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate KPI 2 analysis."""
        coverage = eval_data.get("kpi_2_protocol_coverage", {})
        metrics = coverage.get("metrics", {})
        interpretation = coverage.get("interpretation", {})
        
        return {
            "title": "KPI 2: Protocol Coverage",
            "description": "Number of active honeypot protocols capturing sessions",
            "metrics": metrics,
            "key_findings": [
                f"Active Protocols: {metrics.get('active_protocol_count', 0)}/4",
                f"Active Protocols: {', '.join(metrics.get('active_protocols', []))}",
                f"Total Sessions Captured: {metrics.get('total_sessions', 0)}",
                f"Sessions per Protocol: {metrics.get('sessions_per_protocol', {})}",
            ],
            "interpretation": interpretation,
            "recommendations": self._get_coverage_recommendations(metrics),
        }
    
    def _generate_logging_accuracy_analysis(self, eval_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate KPI 3 analysis."""
        accuracy = eval_data.get("kpi_3_logging_accuracy", {})
        metrics = accuracy.get("metrics", {})
        interpretation = accuracy.get("interpretation", {})
        
        return {
            "title": "KPI 3: Logging Accuracy",
            "description": "Percentage of sessions fully logged without data loss under concurrent load",
            "metrics": metrics,
            "key_findings": [
                f"Overall Logging Accuracy: {metrics.get('overall_logging_accuracy_percent', 0):.1f}%",
                f"Fully Logged Sessions: {metrics.get('fully_logged_sessions', 0)}/{metrics.get('total_sessions', 0)}",
                f"Sessions with Data Loss: {metrics.get('data_loss_detected_sessions', 0)}",
                f"Command Coverage: {metrics.get('average_command_coverage_percent', 0):.1f}%",
                f"Login Coverage: {metrics.get('average_login_coverage_percent', 0):.1f}%",
            ],
            "interpretation": interpretation,
            "recommendations": self._get_accuracy_recommendations(metrics),
        }
    
    def _generate_response_time_analysis(self, eval_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate KPI 4 analysis."""
        response_time = eval_data.get("kpi_4_system_response_time", {})
        metrics = response_time.get("metrics", {})
        interpretation = response_time.get("interpretation", {})
        
        return {
            "title": "KPI 4: System Response Time",
            "description": "Average latency from connection arrival to session log write",
            "metrics": metrics,
            "key_findings": [
                f"Average Response Time: {metrics.get('average_ms', 0):.1f}ms",
                f"P95 Response Time: {metrics.get('p95_ms', 0):.1f}ms",
                f"P99 Response Time: {metrics.get('p99_ms', 0):.1f}ms",
                f"Max Response Time: {metrics.get('max_ms', 0):.1f}ms",
                f"Total Samples: {metrics.get('total_samples', 0)}",
            ],
            "interpretation": interpretation,
            "recommendations": self._get_response_time_recommendations(metrics),
        }
    
    def _generate_recommendations(self, eval_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall recommendations."""
        recommendations = {
            "title": "Recommendations",
            "overall": [],
            "priority_actions": [],
        }
        
        # Analyze each KPI and add recommendations
        detection = eval_data.get("kpi_1_attack_detection_rate", {}).get("metrics", {})
        if detection.get("attack_detection_rate", 0) < 80:
            recommendations["priority_actions"].append(
                "Improve ML model accuracy: Current attack detection rate is below 80%. "
                "Consider retraining model with more diverse attack patterns."
            )
        
        coverage = eval_data.get("kpi_2_protocol_coverage", {}).get("metrics", {})
        if coverage.get("active_protocol_count", 0) < 4:
            recommendations["priority_actions"].append(
                f"Enable missing protocols: Only {coverage.get('active_protocol_count', 0)}/4 protocols active. "
                "Ensure all honeypot listeners are properly configured."
            )
        
        accuracy = eval_data.get("kpi_3_logging_accuracy", {}).get("metrics", {})
        if accuracy.get("overall_logging_accuracy_percent", 0) < 99:
            recommendations["priority_actions"].append(
                "Investigate logging pipeline: Implement data loss monitoring and recovery mechanisms."
            )
        
        response = eval_data.get("kpi_4_system_response_time", {}).get("metrics", {})
        if response.get("average_ms", 0) > 50:
            recommendations["priority_actions"].append(
                "Optimize system performance: Average response time exceeds 50ms. "
                "Profile and optimize critical code paths."
            )
        
        # General recommendations
        recommendations["overall"] = [
            "Implement automated KPI monitoring dashboard for real-time system health tracking",
            "Establish baseline metrics from regular evaluation cycles",
            "Create alerting mechanism for KPI threshold breaches",
            "Document system performance trends over time",
            "Conduct regular adversarial testing with diverse attack patterns",
            "Review and optimize resource allocation based on protocol usage patterns",
        ]
        
        return recommendations
    
    def _get_detection_recommendations(self, metrics: Dict[str, Any]) -> List[str]:
        """Get recommendations for detection rate."""
        recs = []
        if metrics.get("attack_detection_rate", 0) < 90:
            recs.append("Increase attack detection rate by extending training data with more attack variants")
        if metrics.get("false_positive_rate", 0) > 15:
            recs.append("Reduce false positive rate through threshold tuning and feature engineering")
        if metrics.get("precision", 0) < 85:
            recs.append("Improve precision to reduce unnecessary alerts and false alarms")
        return recs or ["Current detection performance is acceptable"]
    
    def _get_coverage_recommendations(self, metrics: Dict[str, Any]) -> List[str]:
        """Get recommendations for protocol coverage."""
        recs = []
        active = metrics.get("active_protocol_count", 0)
        if active < 4:
            recs.append(f"Activate missing protocols. Currently {active}/4 protocols active")
        if metrics.get("total_sessions", 0) < 100:
            recs.append("Generate more traffic to better utilize all protocol handlers")
        return recs or ["Protocol coverage is at full capacity"]
    
    def _get_accuracy_recommendations(self, metrics: Dict[str, Any]) -> List[str]:
        """Get recommendations for logging accuracy."""
        recs = []
        accuracy = metrics.get("overall_logging_accuracy_percent", 0)
        if accuracy < 99:
            recs.append(f"Current logging accuracy is {accuracy:.1f}%. Target 99.9%+ for production")
        if metrics.get("data_loss_detected_sessions", 0) > 0:
            recs.append("Investigate and fix data loss incidents in logging pipeline")
        return recs or ["Logging accuracy meets production standards"]
    
    def _get_response_time_recommendations(self, metrics: Dict[str, Any]) -> List[str]:
        """Get recommendations for response time."""
        recs = []
        avg_ms = metrics.get("average_ms", 0)
        if avg_ms > 10:
            recs.append(f"Optimize latency: Current {avg_ms:.1f}ms exceeds 10ms target")
        p99_ms = metrics.get("p99_ms", 0)
        if p99_ms > 100:
            recs.append("Investigate tail latencies: P99 response time is {p99_ms:.1f}ms")
        return recs or ["Response times are within target ranges"]
    
    def _build_markdown_report(self, eval_data: Dict[str, Any]) -> str:
        """Build Markdown formatted report."""
        md = []
        md.append(f"# Objective 4: System Effectiveness Evaluation Report")
        md.append(f"\n**Report ID:** {self.report_id}")
        md.append(f"\n**Generated:** {self.timestamp.isoformat()}")
        md.append("\n")
        
        # Executive Summary
        md.append("## Executive Summary\n")
        metadata = eval_data.get("evaluation_metadata", {})
        md.append(f"- **Total Scenarios:** {metadata.get('scenarios_run', 0)}")
        md.append(f"- **Successful:** {metadata.get('scenarios_passed', 0)}")
        md.append(f"- **Failed:** {metadata.get('scenarios_failed', 0)}")
        md.append(f"- **Success Rate:** {metadata.get('scenario_success_rate', 0):.1f}%")
        md.append(f"- **Duration:** {metadata.get('total_duration_seconds', 0):.1f} seconds\n")
        
        # KPI Results
        md.append("## KPI Results\n")
        
        detection = eval_data.get("kpi_1_attack_detection_rate", {})
        metrics = detection.get("metrics", {})
        md.append("### KPI 1: Attack Detection Rate\n")
        md.append(f"- Attack Detection Rate: **{metrics.get('attack_detection_rate', 0):.1f}%**")
        md.append(f"- True Positive Rate: {metrics.get('true_positive_rate', 0):.1f}%")
        md.append(f"- False Positive Rate: {metrics.get('false_positive_rate', 0):.1f}%")
        md.append(f"- Precision: {metrics.get('precision', 0):.1f}%")
        md.append(f"- F1 Score: {metrics.get('f1_score', 0):.1f}%\n")
        
        coverage = eval_data.get("kpi_2_protocol_coverage", {})
        metrics = coverage.get("metrics", {})
        md.append("### KPI 2: Protocol Coverage\n")
        md.append(f"- Active Protocols: **{metrics.get('active_protocol_count', 0)}/4**")
        md.append(f"- Protocols: {', '.join(metrics.get('active_protocols', []))}")
        md.append(f"- Total Sessions: {metrics.get('total_sessions', 0)}\n")
        
        accuracy = eval_data.get("kpi_3_logging_accuracy", {})
        metrics = accuracy.get("metrics", {})
        md.append("### KPI 3: Logging Accuracy\n")
        md.append(f"- Overall Accuracy: **{metrics.get('overall_logging_accuracy_percent', 0):.1f}%**")
        md.append(f"- Fully Logged: {metrics.get('fully_logged_sessions', 0)}/{metrics.get('total_sessions', 0)}")
        md.append(f"- Command Coverage: {metrics.get('average_command_coverage_percent', 0):.1f}%\n")
        
        response_time = eval_data.get("kpi_4_system_response_time", {})
        metrics = response_time.get("metrics", {})
        md.append("### KPI 4: Response Time\n")
        md.append(f"- Average: **{metrics.get('average_ms', 0):.1f} ms**")
        md.append(f"- P95: {metrics.get('p95_ms', 0):.1f} ms")
        md.append(f"- P99: {metrics.get('p99_ms', 0):.1f} ms")
        md.append(f"- Max: {metrics.get('max_ms', 0):.1f} ms\n")
        
        return "\n".join(md)
    
    def _build_html_report(self, eval_data: Dict[str, Any]) -> str:
        """Build HTML formatted report with CSS."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.report_id}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            padding: 40px;
        }}
        header {{
            border-bottom: 3px solid #667eea;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        h1 {{
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        h2 {{
            color: #667eea;
            font-size: 1.8em;
            margin-top: 30px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
            padding-left: 15px;
        }}
        h3 {{
            color: #555;
            font-size: 1.3em;
            margin-top: 20px;
            margin-bottom: 10px;
        }}
        .metadata {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
            font-size: 0.95em;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .metric-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .metric-label {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
        .kpi-section {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #667eea;
        }}
        .findings-list {{
            list-style-position: inside;
            margin: 15px 0;
        }}
        .findings-list li {{
            padding: 8px 0;
            border-bottom: 1px solid #e0e0e0;
        }}
        .findings-list li:last-child {{
            border-bottom: none;
        }}
        .status-excellent {{
            color: #28a745;
            font-weight: bold;
        }}
        .status-good {{
            color: #20c997;
            font-weight: bold;
        }}
        .status-acceptable {{
            color: #ffc107;
            font-weight: bold;
        }}
        .status-needs-improvement {{
            color: #fd7e14;
            font-weight: bold;
        }}
        .status-critical {{
            color: #dc3545;
            font-weight: bold;
        }}
        .recommendations {{
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }}
        .recommendations h4 {{
            color: #2196F3;
            margin-bottom: 10px;
        }}
        .recommendations ul {{
            margin-left: 20px;
        }}
        .recommendations li {{
            margin: 8px 0;
        }}
        footer {{
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            text-align: center;
            color: #999;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🍯 PhantomPot KPI Evaluation Report</h1>
            <p><strong>Objective 4:</strong> System Effectiveness Evaluation via measurable KPIs</p>
        </header>
        
        <div class="metadata">
            <p><strong>Report ID:</strong> {self.report_id}</p>
            <p><strong>Generated:</strong> {self.timestamp.isoformat()}</p>
        </div>
        
        <section>
            <h2>Executive Summary</h2>
            <div class="metrics-grid">
"""
        
        # Add metrics
        metadata = eval_data.get("evaluation_metadata", {})
        metrics_data = [
            ("Total Scenarios", str(metadata.get("scenarios_run", 0))),
            ("Successful", str(metadata.get("scenarios_passed", 0))),
            ("Success Rate", f"{metadata.get('scenario_success_rate', 0):.1f}%"),
        ]
        
        for label, value in metrics_data:
            html += f"""                <div class="metric-card">
                    <div class="metric-label">{label}</div>
                    <div class="metric-value">{value}</div>
                </div>
"""
        
        html += """            </div>
        </section>
        
        <section>
            <h2>KPI Evaluation Results</h2>
"""
        
        # KPI 1
        detection = eval_data.get("kpi_1_attack_detection_rate", {})
        metrics = detection.get("metrics", {})
        html += f"""            <div class="kpi-section">
                <h3>KPI 1: Attack Detection Rate</h3>
                <p>{detection.get('description', '')}</p>
                <h4>Key Metrics:</h4>
                <ul class="findings-list">
                    <li><strong>Attack Detection Rate:</strong> {metrics.get('attack_detection_rate', 0):.1f}%</li>
                    <li><strong>True Positive Rate:</strong> {metrics.get('true_positive_rate', 0):.1f}%</li>
                    <li><strong>False Positive Rate:</strong> {metrics.get('false_positive_rate', 0):.1f}%</li>
                    <li><strong>Precision:</strong> {metrics.get('precision', 0):.1f}%</li>
                    <li><strong>F1 Score:</strong> {metrics.get('f1_score', 0):.1f}%</li>
                </ul>
            </div>
"""
        
        # KPI 2
        coverage = eval_data.get("kpi_2_protocol_coverage", {})
        metrics = coverage.get("metrics", {})
        html += f"""            <div class="kpi-section">
                <h3>KPI 2: Protocol Coverage</h3>
                <p>{coverage.get('description', '')}</p>
                <h4>Key Metrics:</h4>
                <ul class="findings-list">
                    <li><strong>Active Protocols:</strong> {metrics.get('active_protocol_count', 0)}/4</li>
                    <li><strong>Protocols:</strong> {', '.join(metrics.get('active_protocols', []))}</li>
                    <li><strong>Total Sessions:</strong> {metrics.get('total_sessions', 0)}</li>
                </ul>
            </div>
"""
        
        # KPI 3
        accuracy = eval_data.get("kpi_3_logging_accuracy", {})
        metrics = accuracy.get("metrics", {})
        html += f"""            <div class="kpi-section">
                <h3>KPI 3: Logging Accuracy</h3>
                <p>{accuracy.get('description', '')}</p>
                <h4>Key Metrics:</h4>
                <ul class="findings-list">
                    <li><strong>Overall Logging Accuracy:</strong> {metrics.get('overall_logging_accuracy_percent', 0):.1f}%</li>
                    <li><strong>Fully Logged Sessions:</strong> {metrics.get('fully_logged_sessions', 0)}/{metrics.get('total_sessions', 0)}</li>
                    <li><strong>Command Coverage:</strong> {metrics.get('average_command_coverage_percent', 0):.1f}%</li>
                </ul>
            </div>
"""
        
        # KPI 4
        response_time = eval_data.get("kpi_4_system_response_time", {})
        metrics = response_time.get("metrics", {})
        html += f"""            <div class="kpi-section">
                <h3>KPI 4: Response Time</h3>
                <p>{response_time.get('description', '')}</p>
                <h4>Key Metrics:</h4>
                <ul class="findings-list">
                    <li><strong>Average Response Time:</strong> {metrics.get('average_ms', 0):.1f} ms</li>
                    <li><strong>P95 Response Time:</strong> {metrics.get('p95_ms', 0):.1f} ms</li>
                    <li><strong>P99 Response Time:</strong> {metrics.get('p99_ms', 0):.1f} ms</li>
                    <li><strong>Max Response Time:</strong> {metrics.get('max_ms', 0):.1f} ms</li>
                </ul>
            </div>
"""
        
        html += """        </section>
        
        <footer>
            <p>This report was automatically generated by PhantomPot KPI Evaluation Framework</p>
        </footer>
    </div>
</body>
</html>
"""
        return html


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate KPI evaluation reports for Objective 4"
    )
    parser.add_argument(
        "--eval", type=Path, required=True,
        help="Path to evaluation results JSON file (from evaluate_objective4.py)"
    )
    parser.add_argument(
        "--format", choices=["json", "markdown", "html", "all"], default="html",
        help="Report format (default: html)"
    )
    parser.add_argument(
        "--output", type=Path, default=Path("objective4_report"),
        help="Output directory or file path (default: objective4_report)"
    )
    
    args = parser.parse_args()
    
    # Load evaluation data
    if not args.eval.exists():
        print(f"Error: Evaluation file not found: {args.eval}")
        sys.exit(1)
    
    eval_data = json.loads(args.eval.read_text())
    
    # Generate reports
    generator = ObjectiveKPIReportGenerator(output_dir=args.output.parent if args.format != "all" else args.output)
    
    generated_files = []
    
    if args.format in ("json", "all"):
        output_path = generator.generate_json_report(eval_data)
        generated_files.append(output_path)
        print(f"[✓] JSON report generated: {output_path}")
    
    if args.format in ("markdown", "all"):
        output_path = generator.generate_markdown_report(eval_data)
        generated_files.append(output_path)
        print(f"[✓] Markdown report generated: {output_path}")
    
    if args.format in ("html", "all"):
        output_path = generator.generate_html_report(eval_data)
        generated_files.append(output_path)
        print(f"[✓] HTML report generated: {output_path}")
    
    print(f"\n[✓] {len(generated_files)} report(s) successfully generated")
    for f in generated_files:
        print(f"    - {f}")


if __name__ == "__main__":
    main()
