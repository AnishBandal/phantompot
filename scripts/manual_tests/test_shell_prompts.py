#!/usr/bin/env python3
"""Test script to demonstrate dynamic shell prompts."""

from src.ssh.fake_shell import ShellSession, generate_prompt

def test_prompts():
    """Demonstrate various shell prompts."""
    print("=" * 70)
    print("TESTING DYNAMIC SHELL PROMPTS")
    print("=" * 70 + "\n")
    
    # Test regular user
    print("1. Regular user 'admin' in home directory:")
    shell = ShellSession("admin")
    print(f"   Prompt: {shell.get_prompt()}")
    
    # Test root user
    print("\n2. Root user in home directory:")
    shell_root = ShellSession("root")
    print(f"   Prompt: {shell_root.get_prompt()}")
    
    # Test directory navigation
    print("\n3. Admin navigating directories:")
    shell_nav = ShellSession("admin")
    
    print(f"   Initial: {shell_nav.get_prompt()}")
    shell_nav.change_dir("/etc")
    print(f"   cd /etc: {shell_nav.get_prompt()}")
    shell_nav.change_dir("passwd")
    print(f"   cd passwd: {shell_nav.get_prompt()}")
    shell_nav.change_dir("..")
    print(f"   cd ..: {shell_nav.get_prompt()}")
    shell_nav.change_dir("~")
    print(f"   cd ~: {shell_nav.get_prompt()}")
    
    # Test root navigation
    print("\n4. Root navigating directories:")
    shell_root_nav = ShellSession("root")
    
    print(f"   Initial: {shell_root_nav.get_prompt()}")
    shell_root_nav.change_dir("/var")
    print(f"   cd /var: {shell_root_nav.get_prompt()}")
    shell_root_nav.change_dir("log")
    print(f"   cd log: {shell_root_nav.get_prompt()}")
    shell_root_nav.change_dir("/")
    print(f"   cd /: {shell_root_nav.get_prompt()}")
    
    # Test different usernames
    print("\n5. Different user accounts:")
    for username in ["alice", "bob", "postgres", "www-data"]:
        shell = ShellSession(username)
        print(f"   {username:12} -> {shell.get_prompt()}")
    
    print("\n" + "=" * 70)
    print("COMPARISON: OLD vs NEW PROMPTS")
    print("=" * 70)
    print("OLD (before): $ ")
    print("NEW (after):  admin@honeypot:~$ ")
    print("              root@honeypot:/root# ")
    print("              alice@honeypot:/home/alice$ ")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    test_prompts()
