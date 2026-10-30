"""ProjectOSINT desktop launcher.

Double-click this file, run ``python ProjectOSINT.py``, or use the frozen
``ProjectOSINT.exe`` built from it: the native desktop app opens.

Base-directory handling: inside a PyInstaller bundle ``__file__`` lives in a
temp extraction folder, so the frozen app anchors on the executable's own
folder instead.  Either way the process ``chdir``s there so ``config.yaml``,
``.env`` and ``data/`` resolve consistently, which is what makes the exe
portable: drop it in any folder, keep its data beside it.
"""

import os
import sys
from pathlib import Path

if getattr(sys, "frozen", False):  # PyInstaller: anchor next to the .exe
    BASE = Path(sys.executable).resolve().parent
else:
    BASE = Path(__file__).resolve().parent

os.chdir(BASE)
sys.path.insert(0, str(BASE))

try:
    from projectosint.desktop import main
except ImportError as exc:
    if "PySide6" in str(exc):
        print(
            "The desktop app needs PySide6. Install it into the venv with:\n"
            '  .venv\\Scripts\\python.exe -m pip install "PySide6-Essentials>=6.7,<7"',
            file=sys.stderr,
        )
        raise SystemExit(1) from exc
    raise

if __name__ == "__main__":
    raise SystemExit(main())
