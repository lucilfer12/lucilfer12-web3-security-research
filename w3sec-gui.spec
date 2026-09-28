from pathlib import Path

ROOT = Path(SPECPATH)
SRC = ROOT / "src"
PACKAGE_ROOT = SRC / "w3sec"

# Derive hidden imports from the repository files themselves. This avoids
# collect_submodules() resolving an unrelated installed w3sec package.
hiddenimports = []
for module_path in PACKAGE_ROOT.rglob("*.py"):
    relative = module_path.relative_to(SRC).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if parts:
        hiddenimports.append(".".join(parts))
hiddenimports = sorted(set(hiddenimports))

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