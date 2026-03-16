"""PyInstaller entry point. Use absolute imports so the bundled script runs correctly."""

from ssh_stats.cli import main

if __name__ == "__main__":
    main()
