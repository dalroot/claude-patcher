"""
Command-Line Interface & Interactive Loop Dispatcher.
"""
import inspect
import sys
import time

from .ui import console, print_header, print_boxed_menu, wait_for_menu_return
from .commands import (
    cmd_doctor,
    cmd_ping,
    cmd_apply,
    cmd_rollback,
    cmd_tz_auto,
    cmd_tz_manual,
    cmd_reset_did,
    cmd_launch_claude,
    cmd_toggle_asar,
)
from .asar import apply_asar_patch, rollback_asar_patch
from .constants import VERSION
from .system import ensure_claude_closed


def interactive_loop():
    """Runs the primary interactive terminal loop."""
    while True:
        print_header()
        print_boxed_menu()
        try:
            choice = input("\n[clp] Select an option [0-8]: ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold yellow]Exiting Claude Patcher. Stay safe![/bold yellow]")
            break

        if choice in ["0", "q", "exit"]:
            console.print("\n[bold yellow]Exiting Claude Patcher. Stay safe![/bold yellow]")
            break
        elif choice == "1":
            cmd_doctor()
            wait_for_menu_return()
        elif choice == "2":
            cmd_ping()
            wait_for_menu_return()
        elif choice == "3":
            cmd_tz_auto()
            wait_for_menu_return()
        elif choice == "4":
            cmd_tz_manual()
            wait_for_menu_return()
        elif choice == "5":
            cmd_apply()
            wait_for_menu_return()
        elif choice == "6":
            cmd_rollback()
            wait_for_menu_return()
        elif choice == "7":
            cmd_reset_did()
            wait_for_menu_return()
        elif choice == "8":
            cmd_launch_claude()
            wait_for_menu_return()
        else:
            console.print("[bold red]Invalid selection. Please choose an option from 0 to 8.[/bold red]")
            time.sleep(1)


def main():
    """CLI entry point for argument parsing and subcommand execution."""
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "doctor":
            cmd_doctor(
                json_output=("--json" in sys.argv),
                check_network=("--offline" not in sys.argv),
            )
        elif cmd == "apply":
            tz = None
            for idx, arg in enumerate(sys.argv[2:], start=2):
                if arg == "--tz":
                    if idx + 1 >= len(sys.argv):
                        console.print("[bold red]✘ --tz requires a timezone argument[/bold red]")
                        sys.exit(1)
                    tz = sys.argv[idx + 1]
                    break
                if arg.startswith("--tz="):
                    tz = arg.split("=", 1)[1]
                    if not tz:
                        console.print("[bold red]✘ --tz requires a non-empty timezone argument[/bold red]")
                        sys.exit(1)
                    break
            cmd_apply(
                tz=tz,
                reset_did=("--reset-did" in sys.argv),
                strict_sift=("--strict-sift" in sys.argv),
            )
        elif cmd == "rollback":
            cmd_rollback()
        elif cmd == "ping":
            cmd_ping()
        elif cmd in ["tz", "timezone"]:
            if len(sys.argv) > 2 and sys.argv[2] == "auto":
                cmd_tz_auto()
            else:
                cmd_tz_manual()
        elif cmd == "reset-did":
            cmd_reset_did()
        elif cmd == "launch":
            cmd_launch_claude()
        elif cmd in ["patch-asar", "patch_asar"]:
            ensure_claude_closed()
            strict_sift = "--strict-sift" in sys.argv
            try:
                if "strict_sift" in inspect.signature(apply_asar_patch).parameters:
                    ok, msg = apply_asar_patch(strict_sift=strict_sift)
                else:
                    ok, msg = apply_asar_patch()
            except Exception as e:
                ok, msg = False, str(e)
            if ok:
                console.print(f"[bold green]✔ {msg}[/bold green]")
            else:
                console.print(f"[bold red]✘ {msg}[/bold red]")
                sys.exit(1)
        elif cmd in ["rollback-asar", "unpatch-asar"]:
            ensure_claude_closed()
            ok, msg = rollback_asar_patch()
            if ok:
                console.print(f"[bold green]✔ {msg}[/bold green]")
            else:
                console.print(f"[bold red]✘ {msg}[/bold red]")
                sys.exit(1)
        elif cmd in ["asar", "toggle-asar"]:
            cmd_toggle_asar()
        elif cmd in ["-h", "--help", "help"]:
            print(f"Claude Patcher CLI v{VERSION} (Linux, Windows & macOS)")
            print("Usage: clp [doctor [--json] [--offline] | apply [--tz <TZ|auto>] [--reset-did] [--strict-sift] | rollback | ping | tz [auto] | reset-did | launch | patch-asar [--strict-sift] | rollback-asar | asar]")
        else:
            print(f"Unknown command: {cmd}. Run 'clp --help' for usage.")
            sys.exit(1)
    else:
        interactive_loop()


if __name__ == "__main__":
    main()
