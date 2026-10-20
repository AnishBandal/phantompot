"""Fake shell responses. Never executes host commands."""

from __future__ import annotations

import os

from typing import Callable, Dict

# Default static prompt (deprecated - use generate_prompt instead)
PROMPT = "$ "

# Hostname shown to SSH clients. Keep this neutral to avoid obvious fingerprinting.
HOSTNAME = os.getenv("SSH_FAKE_HOSTNAME", "SRV-1")


def generate_prompt(username: str = "user", working_dir: str = "~") -> str:
    """
    Generate a realistic shell prompt.
    
    Format:
    - Regular user: username@hostname:directory$ 
    - Root user: root@hostname:directory# 
    
    Args:
        username: Connected username (e.g., 'admin', 'root')
        working_dir: Current working directory (default '~')
    
    Returns:
        Formatted prompt string
    """
    # Root gets # prompt, others get $
    prompt_char = "#" if username == "root" else "$"
    return f"{username}@{HOSTNAME}:{working_dir}{prompt_char} "


class ShellSession:
    """Tracks shell state per SSH session."""
    
    def __init__(self, username: str) -> None:
        self.username = username
        self.working_dir = "~" if username != "root" else "/root"
        self.home_dir = "/root" if username == "root" else f"/home/{username}"
    
    def get_prompt(self) -> str:
        """Return the current prompt."""
        return generate_prompt(self.username, self.working_dir)
    
    def change_dir(self, target: str) -> str:
        """Handle cd command - return feedback message."""
        # Expand ~ to home directory
        if target == "~":
            self.working_dir = self.home_dir
            return ""
        elif target == "/":
            self.working_dir = "/"
            return ""
        elif target.startswith("/"):
            # Absolute path
            self.working_dir = target.rstrip("/") or "/"
            return ""
        elif target == "..":
            # Go up one level
            if self.working_dir == "/":
                self.working_dir = "/"
            else:
                self.working_dir = "/".join(self.working_dir.split("/")[:-1]) or "/"
            return ""
        else:
            # Relative path
            if self.working_dir == "/":
                self.working_dir = f"/{target.rstrip('/')}"
            else:
                self.working_dir = f"{self.working_dir}/{target}".rstrip("/")
            return ""


def _fake_ls(shell: ShellSession, command: str) -> str:
    return "bin  etc  home  tmp  var"


def _fake_pwd(shell: ShellSession, command: str) -> str:
    # Map ~ back to home directory for pwd output
    if shell.working_dir == "~":
        return shell.home_dir
    return shell.working_dir



def _fake_whoami(shell: ShellSession, command: str) -> str:
    return shell.username



def _fake_uname(shell: ShellSession, command: str) -> str:
    return f"Linux {HOSTNAME} 5.15.0-virtual #1 SMP x86_64 GNU/Linux"



def _fake_cd(shell: ShellSession, command: str) -> str:
    """Handle cd (change directory) command."""
    parts = command.split(maxsplit=1)
    if len(parts) == 1:
        # cd with no args = go to home
        shell.change_dir("~")
        return ""
    
    target = parts[1].strip()
    shell.change_dir(target)
    return ""



def _fake_cat(shell: ShellSession, command: str) -> str:
    parts = command.split(maxsplit=1)
    if len(parts) == 1:
        return "cat: missing operand"

    target = parts[1].strip()
    fake_files = {
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash",
        "/etc/shadow": "root:*:19793:0:99999:7:::",
        "readme.txt": "System maintenance window scheduled.",
    }
    return fake_files.get(target, f"cat: {target}: No such file or directory")


def _fake_id(shell: ShellSession, command: str) -> str:
    """Return user/group information."""
    if shell.username == "root":
        return "uid=0(root) gid=0(root) groups=0(root)"
    else:
        uid = 1000 if shell.username == "admin" else 1001
        return f"uid={uid}({shell.username}) gid=1000({shell.username}) groups=1000({shell.username})"


def _fake_hostname(shell: ShellSession, command: str) -> str:
    """Return hostname."""
    return HOSTNAME


def _fake_date(shell: ShellSession, command: str) -> str:
    """Return current date/time (simulated)."""
    return "Mon Apr 14 15:42:37 UTC 2025"


def _fake_echo(shell: ShellSession, command: str) -> str:
    """Echo command - repeat arguments."""
    parts = command.split(maxsplit=1)
    if len(parts) == 1:
        return ""
    return parts[1].strip()


def _fake_mkdir(shell: ShellSession, command: str) -> str:
    """Create directory (fake - always succeeds)."""
    parts = command.split(maxsplit=1)
    if len(parts) == 1:
        return "mkdir: missing operand"
    # Just silently succeed (real mkdir does this too)
    return ""


def _fake_touch(shell: ShellSession, command: str) -> str:
    """Create/update file (fake - always succeeds)."""
    parts = command.split(maxsplit=1)
    if len(parts) == 1:
        return "touch: missing operand"
    # Just silently succeed
    return ""


def _fake_rm(shell: ShellSession, command: str) -> str:
    """Remove file (fake - always succeeds)."""
    parts = command.split(maxsplit=1)
    if len(parts) == 1:
        return "rm: missing operand"
    target = parts[1].strip()
    # Check for dangerous operations
    if target == "/" or target.startswith("/*"):
        return "rm: cannot remove '/' or '/*'"
    # Just silently succeed
    return ""


def _fake_cp(shell: ShellSession, command: str) -> str:
    """Copy file (fake - always succeeds)."""
    parts = command.split()
    if len(parts) < 3:
        return "cp: missing operand"
    # Just silently succeed
    return ""


def _fake_mv(shell: ShellSession, command: str) -> str:
    """Move/rename file (fake - always succeeds)."""
    parts = command.split()
    if len(parts) < 3:
        return "mv: missing operand"
    # Just silently succeed
    return ""


def _fake_grep(shell: ShellSession, command: str) -> str:
    """Search file contents (fake)."""
    parts = command.split()
    if len(parts) < 2:
        return "grep: No such file or directory"
    
    # Simple fake grep that shows some lines
    search_term = parts[1].strip("'\"")
    filename = parts[-1] if len(parts) > 2 else ""
    
    if not filename or filename == search_term:
        return ""
    
    # Return fake grep results
    if "admin" in search_term:
        return f"admin:x:1000:1000:admin:/home/admin:/bin/bash"
    elif "root" in search_term:
        return f"root:x:0:0:root:/root:/bin/bash"
    return ""


def _fake_find(shell: ShellSession, command: str) -> str:
    """Find files (fake)."""
    parts = command.split()
    if len(parts) < 2:
        return "{PATH}: No such file or directory"
    
    # Return fake find results
    search_path = parts[1]
    if "-name" in parts:
        # find /path -name pattern
        idx = parts.index("-name")
        if idx + 1 < len(parts):
            pattern = parts[idx + 1].strip("'\"")
            return f"{search_path}/{pattern}"
    
    # Default fake results
    return f"{search_path}/file1\n{search_path}/file2"


def _fake_sudo(shell: ShellSession, command: str) -> str:
    """Handle sudo command (fake)."""
    parts = command.split(maxsplit=1)
    
    if len(parts) == 1:
        # sudo with no args
        return "usage: sudo [-u user] command"
    
    # sudo command = just echo "command not found" for now
    subcommand = parts[1].split()[0]
    return f"sudo: {subcommand}: command not found"


def _fake_which(shell: ShellSession, command: str) -> str:
    """Show path to command."""
    parts = command.split()
    if len(parts) < 2:
        return ""
    
    cmd = parts[1]
    common_paths = {
        "ls": "/bin/ls",
        "pwd": "/bin/pwd",
        "cat": "/bin/cat",
        "echo": "/bin/echo",
        "grep": "/bin/grep",
        "find": "/usr/bin/find",
        "mkdir": "/bin/mkdir",
        "rm": "/bin/rm",
        "cp": "/bin/cp",
        "mv": "/bin/mv",
        "touch": "/usr/bin/touch",
        "id": "/usr/bin/id",
        "whoami": "/usr/bin/whoami",
        "date": "/bin/date",
        "sudo": "/usr/bin/sudo",
    }
    return common_paths.get(cmd, f"/usr/bin/{cmd}")


def _fake_clear(shell: ShellSession, command: str) -> str:
    """Clear screen (fake - returns empty)."""
    return ""


_COMMAND_HANDLERS: Dict[str, Callable] = {
    "ls": _fake_ls,
    "pwd": _fake_pwd,
    "cd": _fake_cd,
    "whoami": _fake_whoami,
    "uname": _fake_uname,
    "cat": _fake_cat,
    "id": _fake_id,
    "hostname": _fake_hostname,
    "date": _fake_date,
    "echo": _fake_echo,
    "mkdir": _fake_mkdir,
    "touch": _fake_touch,
    "rm": _fake_rm,
    "cp": _fake_cp,
    "mv": _fake_mv,
    "grep": _fake_grep,
    "find": _fake_find,
    "sudo": _fake_sudo,
    "which": _fake_which,
    "clear": _fake_clear,
}



def handle_fake_command(shell: ShellSession, command: str) -> str:
    """
    Handle a fake shell command and return response.
    
    Args:
        shell: ShellSession object tracking user state
        command: Command string to execute
    
    Returns:
        Command response/output
    """
    command = command.strip()
    if not command:
        return ""

    verb = command.split(maxsplit=1)[0]
    handler = _COMMAND_HANDLERS.get(verb)
    if handler is None:
        return f"{verb}: command not found"
    
    # Call handler with shell and command (or just command for stateless handlers)
    try:
        return handler(shell, command)
    except TypeError:
        # Fallback for handlers that don't expect shell parameter
        return handler(command)
