"""
Legacy entry point for the password cracker CLI.

This thin wrapper exists to preserve the original
`python password_cracker.py` workflow while delegating all
real work to the new `cracker.cli` module.
"""

from multiprocessing import freeze_support

from cracker.cli import main


if __name__ == "__main__":
    freeze_support()
    raise SystemExit(main())

