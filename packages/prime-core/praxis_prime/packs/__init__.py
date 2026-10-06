"""Vertical pack loader.

The six regulated packs ship as data under ``packs/regulated``. This loader
reads legacy ``pack.json`` packs as data. Pack Python, JavaScript, and
dashboard files are not executed or served. Hard-coded model pins are ignored.

TODO: ARCHITECTURE §17 and §32. Addendum A §7.
"""

from praxis_prime.packs.install import install_pack, list_installed, load_installed
from praxis_prime.packs.legacy import load_legacy_pack

__all__ = ["install_pack", "list_installed", "load_installed", "load_legacy_pack"]
