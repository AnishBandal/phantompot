"""Key Performance Indicators (KPIs) tracking and calculation for Objective 4."""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set

import pandas as pd


@dataclass
class ResponseTimeMetric:
    """Track response time from session start to log write completion."""
    session_id: str
    protocol: str
    connection_time: float  # Timestamp of connection arrival
    log_write_time: float   # Timestamp of log write completion
    
    @property
    def latency_ms(self) -> float:
        """Latency in milliseconds from connection to log write."""
        return max(0.0, (self.log_write_time - self.connection_time) * 1000.0)


@dataclass
class DetectionMetric:
    """Track ML model detection results against ground truth."""
    session_id: str
    ground_truth: str  # 'attack' or 'normal' (from simulation scenario)
    predicted: str     # 'attack' or 'normal' (from ML model)
    anomaly_score: float
    protocol: str
    
    @property
    def is_true_positive(self) -> bool:
        return self.ground_truth == "attack" and self.predicted == "attack"
    
    @property
    def is_true_negative(self) -> bool:
        return self.ground_truth == "normal" and self.predicted == "normal"
    
    @property
    def is_false_positive(self) -> bool:
        return self.ground_truth == "normal" and self.predicted == "attack"
    
    @property
    def is_false_negative(self) -> bool:
        return self.ground_truth == "attack" and self.predicted == "normal"


@dataclass
class LoggingAccuracyMetric:
    """Validate session data completeness and integrity."""
    session_id: str
    protocol: str
    expected_commands: int
    logged_commands: int
    expected_login_attempts: int
    logged_login_attempts: int
    data_loss_detected: bool
    duration: float
    
    @property
    def command_coverage_percent(self) -> float:
        """Percentage of expected commands successfully logged."""
        if self.expected_commands == 0:
            return 100.0
        return (self.logged_commands / self.expected_commands) * 100.0
    
    @property
    def login_coverage_percent(self) -> float:
        """Percentage of login attempts successfully logged."""
        if self.expected_login_attempts == 0:
            return 100.0
        return (self.logged_login_attempts / self.expected_login_attempts) * 100.0
    
    @property
    def overall_accuracy_percent(self) -> float:
        """Overall logging accuracy across all session events."""
        total_expected = self.expected_commands + self.expected_login_attempts
        if total_expected == 0:
            return 100.0
        total_logged = self.logged_commands + self.logged_login_attempts
        return (total_logged / total_expected) * 100.0


class KPIMetricsCollector:
    """Thread-safe collector for all KPI metrics during testing."""
    
    def __init__(self) -> None:
        self._lock = threading.Lock()
        
        # Response Time Metrics
        self._response_times: List[ResponseTimeMetric] = []
        
        # Detection Metrics
        self._detection_results: List[DetectionMetric] = []
        
        # Logging Accuracy Metrics
        self._logging_accuracy: List[LoggingAccuracyMetric] = []
        
        # Protocol Coverage Tracking
        self._active_protocols: Set[str] = set()
        self._protocol_session_count: Dict[str, int] = defaultdict(int)
    
    # ========================================================================
    # Response Time Tracking
    # ========================================================================
    
    def record_response_time(self, session_id: str, protocol: str, 
                            connection_time: float, log_write_time: float) -> None:
        """Record latency from connection arrival to log write completion."""
        metric = ResponseTimeMetric(
            session_id=session_id,
            protocol=protocol,
            connection_time=connection_time,
            log_write_time=log_write_time
        )
        with self._lock:
            self._response_times.append(metric)
    
    def get_average_response_time_ms(self) -> float:
        """Calculate average system response time in milliseconds."""
        with self._lock:
            if not self._response_times:
                return 0.0
            latencies = [m.latency_ms for m in self._response_times]
            return sum(latencies) / len(latencies)
    
    def get_p95_response_time_ms(self) -> float:
        """Calculate 95th percentile response time in milliseconds."""
        with self._lock:
            if not self._response_times:
                return 0.0
            latencies = sorted([m.latency_ms for m in self._response_times])
            idx = int(len(latencies) * 0.95)
            return latencies[min(idx, len(latencies) - 1)]
    
    def get_p99_response_time_ms(self) -> float:
        """Calculate 99th percentile response time in milliseconds."""
        with self._lock:
            if not self._response_times:
                return 0.0
            latencies = sorted([m.latency_ms for m in self._response_times])
            idx = int(len(latencies) * 0.99)
            return latencies[min(idx, len(latencies) - 1)]
    
    def get_max_response_time_ms(self) -> float:
        """Get maximum response time in milliseconds."""
        with self._lock:
            if not self._response_times:
                return 0.0
            return max(m.latency_ms for m in self._response_times)
    
    # ========================================================================
    # Attack Detection Rate Tracking
    # ========================================================================
    
    def record_detection_result(self, session_id: str, ground_truth: str, 
                               predicted: str, anomaly_score: float, 
                               protocol: str) -> None:
        """Record ML model prediction against ground truth."""
        metric = DetectionMetric(
            session_id=session_id,
            ground_truth=ground_truth,
            predicted=predicted,
            anomaly_score=anomaly_score,
            protocol=protocol
        )
        with self._lock:
            self._detection_results.append(metric)
    
    def get_detection_metrics(self) -> Dict[str, Any]:
        """Calculate attack detection metrics (TP, FP, TPR, FPR, etc.)."""
        with self._lock:
            if not self._detection_results:
                return {
                    "total_sessions": 0,
                    "true_positives": 0,
                    "true_negatives": 0,
                    "false_positives": 0,
                    "false_negatives": 0,
                    "attack_detection_rate": 0.0,
                    "true_positive_rate": 0.0,
                    "false_positive_rate": 0.0,
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1_score": 0.0,
                    "accuracy": 0.0,
                }
            
            results = self._detection_results
            
            tp = sum(1 for m in results if m.is_true_positive)
            tn = sum(1 for m in results if m.is_true_negative)
            fp = sum(1 for m in results if m.is_false_positive)
            fn = sum(1 for m in results if m.is_false_negative)
            
            total = len(results)
            
            # Attack Detection Rate: percentage of attacks successfully identified
            attack_detection_rate = (tp / (tp + fn)) * 100.0 if (tp + fn) > 0 else 0.0
            
            # True Positive Rate (Sensitivity/Recall)
            tpr = (tp / (tp + fn)) * 100.0 if (tp + fn) > 0 else 0.0
            
            # False Positive Rate
            fpr = (fp / (fp + tn)) * 100.0 if (fp + tn) > 0 else 0.0
            
            # Precision
            precision = (tp / (tp + fp)) * 100.0 if (tp + fp) > 0 else 0.0
            
            # Recall (same as TPR)
            recall = tpr
            
            # F1 Score
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
            
            # Overall Accuracy
            accuracy = ((tp + tn) / total) * 100.0 if total > 0 else 0.0
            
            return {
                "total_sessions": total,
                "true_positives": tp,
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn,
                "attack_detection_rate": attack_detection_rate,
                "true_positive_rate": tpr,
                "false_positive_rate": fpr,
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "accuracy": accuracy,
            }
    
    def get_detection_metrics_by_protocol(self) -> Dict[str, Dict[str, Any]]:
        """Get detection metrics broken down by protocol."""
        with self._lock:
            by_protocol: Dict[str, List[DetectionMetric]] = defaultdict(list)
            for metric in self._detection_results:
                by_protocol[metric.protocol].append(metric)
            
            result = {}
            for protocol, metrics in by_protocol.items():
                if not metrics:
                    continue
                
                tp = sum(1 for m in metrics if m.is_true_positive)
                tn = sum(1 for m in metrics if m.is_true_negative)
                fp = sum(1 for m in metrics if m.is_false_positive)
                fn = sum(1 for m in metrics if m.is_false_negative)
                total = len(metrics)
                
                tpr = (tp / (tp + fn)) * 100.0 if (tp + fn) > 0 else 0.0
                fpr = (fp / (fp + tn)) * 100.0 if (fp + tn) > 0 else 0.0
                precision = (tp / (tp + fp)) * 100.0 if (tp + fp) > 0 else 0.0
                f1 = 2 * (precision * tpr) / (precision + tpr) if (precision + tpr) > 0 else 0.0
                accuracy = ((tp + tn) / total) * 100.0 if total > 0 else 0.0
                
                result[protocol] = {
                    "total_sessions": total,
                    "true_positives": tp,
                    "true_negatives": tn,
                    "false_positives": fp,
                    "false_negatives": fn,
                    "true_positive_rate": tpr,
                    "false_positive_rate": fpr,
                    "precision": precision,
                    "f1_score": f1,
                    "accuracy": accuracy,
                }
            
            return result
    
    # ========================================================================
    # Protocol Coverage Tracking
    # ========================================================================
    
    def mark_protocol_active(self, protocol: str) -> None:
        """Mark a protocol as having active sessions."""
        with self._lock:
            self._active_protocols.add(protocol)
    
    def increment_protocol_session_count(self, protocol: str) -> None:
        """Increment session count for a protocol."""
        with self._lock:
            self._protocol_session_count[protocol] += 1
    
    def get_protocol_coverage(self) -> Dict[str, Any]:
        """Get protocol coverage metrics."""
        with self._lock:
            active_count = len(self._active_protocols)
            total_sessions = sum(self._protocol_session_count.values())
            
            coverage_by_protocol = dict(self._protocol_session_count)
            active_protocols_list = sorted(list(self._active_protocols))
            
            return {
                "active_protocol_count": active_count,
                "active_protocols": active_protocols_list,
                "total_sessions": total_sessions,
                "sessions_per_protocol": coverage_by_protocol,
            }
    
    # ========================================================================
    # Logging Accuracy Tracking
    # ========================================================================
    
    def record_logging_accuracy(self, session_id: str, protocol: str,
                               expected_commands: int, logged_commands: int,
                               expected_login_attempts: int, logged_login_attempts: int,
                               data_loss_detected: bool, duration: float) -> None:
        """Record logging accuracy for a session."""
        metric = LoggingAccuracyMetric(
            session_id=session_id,
            protocol=protocol,
            expected_commands=expected_commands,
            logged_commands=logged_commands,
            expected_login_attempts=expected_login_attempts,
            logged_login_attempts=logged_login_attempts,
            data_loss_detected=data_loss_detected,
            duration=duration
        )
        with self._lock:
            self._logging_accuracy.append(metric)
    
    def get_logging_accuracy_metrics(self) -> Dict[str, Any]:
        """Calculate logging accuracy under concurrent load."""
        with self._lock:
            if not self._logging_accuracy:
                return {
                    "total_sessions": 0,
                    "fully_logged_sessions": 0,
                    "data_loss_detected_sessions": 0,
                    "average_command_coverage_percent": 0.0,
                    "average_login_coverage_percent": 0.0,
                    "overall_logging_accuracy_percent": 0.0,
                    "sessions_with_full_integrity": 0,
                    "integrity_rate_percent": 0.0,
                }
            
            metrics = self._logging_accuracy
            total = len(metrics)
            
            fully_logged = sum(1 for m in metrics if not m.data_loss_detected)
            data_loss_count = sum(1 for m in metrics if m.data_loss_detected)
            
            avg_cmd_coverage = sum(m.command_coverage_percent for m in metrics) / total if total > 0 else 0.0
            avg_login_coverage = sum(m.login_coverage_percent for m in metrics) / total if total > 0 else 0.0
            avg_overall = sum(m.overall_accuracy_percent for m in metrics) / total if total > 0 else 0.0
            
            full_integrity_count = sum(1 for m in metrics 
                                      if m.command_coverage_percent == 100.0 
                                      and m.login_coverage_percent == 100.0)
            
            return {
                "total_sessions": total,
                "fully_logged_sessions": fully_logged,
                "data_loss_detected_sessions": data_loss_count,
                "average_command_coverage_percent": avg_cmd_coverage,
                "average_login_coverage_percent": avg_login_coverage,
                "overall_logging_accuracy_percent": avg_overall,
                "sessions_with_full_integrity": full_integrity_count,
                "integrity_rate_percent": (full_integrity_count / total) * 100.0 if total > 0 else 0.0,
            }
    
    def get_logging_accuracy_by_protocol(self) -> Dict[str, Dict[str, Any]]:
        """Get logging accuracy metrics broken down by protocol."""
        with self._lock:
            by_protocol: Dict[str, List[LoggingAccuracyMetric]] = defaultdict(list)
            for metric in self._logging_accuracy:
                by_protocol[metric.protocol].append(metric)
            
            result = {}
            for protocol, metrics in by_protocol.items():
                if not metrics:
                    continue
                
                total = len(metrics)
                fully_logged = sum(1 for m in metrics if not m.data_loss_detected)
                data_loss_count = sum(1 for m in metrics if m.data_loss_detected)
                
                avg_cmd_coverage = sum(m.command_coverage_percent for m in metrics) / total if total > 0 else 0.0
                avg_login_coverage = sum(m.login_coverage_percent for m in metrics) / total if total > 0 else 0.0
                avg_overall = sum(m.overall_accuracy_percent for m in metrics) / total if total > 0 else 0.0
                
                full_integrity = sum(1 for m in metrics 
                                    if m.command_coverage_percent == 100.0 
                                    and m.login_coverage_percent == 100.0)
                
                result[protocol] = {
                    "total_sessions": total,
                    "fully_logged_sessions": fully_logged,
                    "data_loss_detected_sessions": data_loss_count,
                    "average_command_coverage_percent": avg_cmd_coverage,
                    "average_login_coverage_percent": avg_login_coverage,
                    "overall_logging_accuracy_percent": avg_overall,
                    "sessions_with_full_integrity": full_integrity,
                    "integrity_rate_percent": (full_integrity / total) * 100.0 if total > 0 else 0.0,
                }
            
            return result
    
    # ========================================================================
    # Summary & Export
    # ========================================================================
    
    def get_all_kpi_summary(self) -> Dict[str, Any]:
        """Get complete KPI summary across all four objectives."""
        return {
            "response_time": {
                "average_ms": self.get_average_response_time_ms(),
                "p95_ms": self.get_p95_response_time_ms(),
                "p99_ms": self.get_p99_response_time_ms(),
                "max_ms": self.get_max_response_time_ms(),
                "total_samples": len(self._response_times),
            },
            "attack_detection": self.get_detection_metrics(),
            "attack_detection_by_protocol": self.get_detection_metrics_by_protocol(),
            "protocol_coverage": self.get_protocol_coverage(),
            "logging_accuracy": self.get_logging_accuracy_metrics(),
            "logging_accuracy_by_protocol": self.get_logging_accuracy_by_protocol(),
        }
    
    def export_to_dataframe(self) -> pd.DataFrame:
        """Export all metrics as pandas DataFrame for analysis."""
        rows = []
        
        with self._lock:
            for rt_metric in self._response_times:
                row = {"metric_type": "response_time", "session_id": rt_metric.session_id}
                row["protocol"] = rt_metric.protocol
                row["latency_ms"] = rt_metric.latency_ms
                rows.append(row)
            
            for det_metric in self._detection_results:
                row = {"metric_type": "detection", "session_id": det_metric.session_id}
                row["protocol"] = det_metric.protocol
                row["ground_truth"] = det_metric.ground_truth
                row["predicted"] = det_metric.predicted
                row["anomaly_score"] = det_metric.anomaly_score
                row["is_correct"] = (det_metric.ground_truth == det_metric.predicted)
                rows.append(row)
            
            for acc_metric in self._logging_accuracy:
                row = {"metric_type": "logging_accuracy", "session_id": acc_metric.session_id}
                row["protocol"] = acc_metric.protocol
                row["command_coverage"] = acc_metric.command_coverage_percent
                row["login_coverage"] = acc_metric.login_coverage_percent
                row["overall_accuracy"] = acc_metric.overall_accuracy_percent
                row["data_loss_detected"] = acc_metric.data_loss_detected
                rows.append(row)
        
        return pd.DataFrame(rows) if rows else pd.DataFrame()
