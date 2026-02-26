#!/usr/bin/env python3
from vulsentinel.cli import main


if __name__ == "__main__":
    raise SystemExit(main(prog="vulsentinel_cli", include_openai_overrides=True))
