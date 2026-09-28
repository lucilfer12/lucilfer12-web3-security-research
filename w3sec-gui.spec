from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH)
SRC = ROOT / "src"

# Keep explicit core imports in addition to recursive discovery. The project
# contains both legacy audit.py and the audit/ package, so automatic discovery
# must not be the only mechanism that retains w3sec.intake in the GUI bundle.
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
