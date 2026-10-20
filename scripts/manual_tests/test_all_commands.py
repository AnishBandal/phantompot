#!/usr/bin/env python3
"""Test script to demonstrate all supported SSH shell commands."""

from src.ssh.fake_shell import ShellSession, handle_fake_command

def test_all_commands():
    """Test all implemented shell commands."""
    print("=" * 80)
    print("TESTING ALL SSH HONEYPOT SHELL COMMANDS")
    print("=" * 80 + "\n")
    
    # Create a shell session for a regular user
    shell = ShellSession("alice")
    
    # Test cases: (command, expected_contains)
    test_cases = [
        ("ls", "bin  etc  home"),
        ("pwd", "/home/alice"),
        ("whoami", "alice"),
        ("id", "uid=1001(alice)"),
        ("hostname", "honeypot"),
        ("date", "2025"),
        ("uname", "Linux honeypot"),
        ("echo hello world", "hello world"),
        ("which ls", "/bin/ls"),
        ("cd /var", ""),  # cd produces no output
        ("pwd", "/var"),   # But pwd shows we're in /var now
        ("mkdir test_dir", ""),
        ("touch myfile.txt", ""),
        ("cp source.txt dest.txt", ""),
        ("mv oldname.txt newname.txt", ""),
        ("rm somefile.txt", ""),
        ("grep admin /etc/passwd", "admin"),
        ("find /home -name file", "/home/file"),
        ("sudo ls -la", "sudo:"),
        ("unknown_command", "unknown_command: command not found"),
    ]
    
    print("Running command tests:\n")
    for i, (command, expected) in enumerate(test_cases, 1):
        result = handle_fake_command(shell, command)
        status = "✓" if (expected in result or expected == "") else "✗"
        print(f"{status} [{i:2d}] {command:35} → {result[:50]}")
    
    print("\n" + "=" * 80)
    print("DETAILED COMMAND EXAMPLES")
    print("=" * 80 + "\n")
    
    # Reset shell
    shell = ShellSession("admin")
    
    examples = [
        ("Regular User Session", [
            ("whoami", "admin"),
            ("id", "uid/gid info"),
            ("pwd", "/home/admin"),
            ("echo 'Attack payload'", "reflect input"),
            ("hostname", "honeypot"),
        ]),
        ("Root User Session", [
            ("whoami", "root"),
            ("id", "uid=0"),
        ]),
        ("Directory Navigation", [
            ("pwd", "current path"),
            ("cd /etc", "change to /etc"),
            ("pwd", "/etc"),
            ("cd ..", "go up"),
            ("pwd", "/"),
        ]),
        ("File Operations", [
            ("mkdir mydir", "creates dir"),
            ("touch file.txt", "creates file"),
            ("cp src.txt dst.txt", "copies file"),
            ("mv old.txt new.txt", "moves file"),
            ("rm unwanted.txt", "deletes file"),
        ]),
        ("Search Commands", [
            ("grep admin /etc/passwd", "find matching lines"),
            ("find /home -name '*.txt'", "search files"),
            ("which python", "locate command"),
        ]),
    ]
    
    for category, commands in examples:
        print(f"\n📋 {category}:")
        print("-" * 80)
        shell = ShellSession("admin")
        for cmd, description in commands:
            result = handle_fake_command(shell, cmd)
            result_preview = result[:60] if result else "(no output)"
            print(f"  • {cmd:30} → {result_preview}")
    
    print("\n" + "=" * 80)
    print("COMMAND REFERENCE")
    print("=" * 80 + "\n")
    
    commands_info = [
        ("ls", "List directory contents", "ls"),
        ("pwd", "Print working directory", "pwd"),
        ("cd", "Change directory", "cd /etc, cd .., cd ~"),
        ("whoami", "Show current username", "whoami"),
        ("id", "Show user/group info", "id"),
        ("hostname", "Show hostname", "hostname"),
        ("date", "Show current date/time", "date"),
        ("echo", "Echo arguments", "echo 'hello world'"),
        ("uname", "Show system info", "uname"),
        ("which", "Locate command", "which ls"),
        ("mkdir", "Create directory", "mkdir newfolder"),
        ("touch", "Create/update file", "touch file.txt"),
        ("rm", "Remove file", "rm file.txt"),
        ("cp", "Copy file", "cp src.txt dst.txt"),
        ("mv", "Move/rename file", "mv old.txt new.txt"),
        ("cat", "Display file contents", "cat /etc/passwd"),
        ("grep", "Search in file", "grep admin /etc/passwd"),
        ("find", "Find files", "find /home -name '*.txt'"),
        ("sudo", "Privilege escalation (fake)", "sudo ls"),
        ("clear", "Clear screen", "clear"),
    ]
    
    print(f"{'Command':<12} {'Description':<35} {'Example':<40}")
    print("-" * 87)
    for cmd, desc, example in commands_info:
        print(f"{cmd:<12} {desc:<35} {example:<40}")
    
    print("\n" + "=" * 80)
    print(f"TOTAL COMMANDS SUPPORTED: {len(commands_info)}")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    test_all_commands()
