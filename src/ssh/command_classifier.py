"""Simple command risk classification."""

from __future__ import annotations

SUSPICIOUS_KEYWORDS = {
    "wget",
    "curl",
    "chmod",
    "nc",
    "bash",
    "sh",
    "python",
    "perl",
}



def is_suspicious_command(command: str) -> bool:
    lowered = command.lower()
    return any(keyword in lowered for keyword in SUSPICIOUS_KEYWORDS)



def classify_command(command: str) -> str:
    return "suspicious" if is_suspicious_command(command) else "benign"
