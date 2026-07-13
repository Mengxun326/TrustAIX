"""Safe local SQLite backup helper used by scheduled production jobs."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path


def backup_sqlite(source: str | Path, destination: str | Path) -> Path:
    source_path, destination_path = Path(source), Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(source_path) as origin, sqlite3.connect(destination_path) as target:
        origin.backup(target)
    return destination_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a consistent TrustAIX SQLite backup.")
    parser.add_argument("source")
    parser.add_argument("destination")
    args = parser.parse_args()
    print(backup_sqlite(args.source, args.destination))


if __name__ == "__main__":
    main()
