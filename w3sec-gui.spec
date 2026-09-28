from pathlib import Path
import sys
from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH)
SRC = ROOT / "src"

# PyInstaller executes the spec before applying Analysis.pathex. Put the local
# source tree first so collect_submodules("w3sec") cannot resolve an older
# installed w3sec package from site-packages instead of this repository.
sys.path.insert(0, str(SRC))

core_hiddenimports = [
    "w3sec.audit",
    "w3sec.audit.__init__",
    "w3sec.intake",
    "w3sec.graph",
    "w3sec.export",
    "w3sec.contract_audit",
]
hiddenimports = sorted(set(collect_submodules("w3sec") + core_hiddenimports))

datas = [(str(ROOT / "backgrounds" / "atlas_forest.jpg"), "backgrounds")]

a = Analysis(
    [str(ROOT / "w3sec_gui_entry.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ATLAS",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
)