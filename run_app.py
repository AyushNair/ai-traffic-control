"""PyInstaller entry point for the AI Traffic Control desktop app."""
import os
import sys

# Prefer the Qt and Shiboken DLLs shipped beside this frozen app. This avoids
# collisions with unrelated Qt installations elsewhere on the Windows PATH.
if getattr(sys, "frozen", False):
    bundle_dir = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    dll_dirs = (os.path.join(bundle_dir, "PySide6"), os.path.join(bundle_dir, "shiboken6"), bundle_dir)
    os.environ["PATH"] = os.pathsep.join((*dll_dirs, os.environ.get("PATH", "")))
    for dll_dir in dll_dirs:
        if os.path.isdir(dll_dir):
            os.add_dll_directory(dll_dir)

from traffic_control.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
