"""The old name of pebin.py (renamed 2026-10-23): kept so code outside Rhipper that still imports
wowbin works. Import pebin."""
from pebin import *  # noqa: F401,F403
from pebin import Binary, Section, hexa, regs_access, write_facts  # noqa: F401
