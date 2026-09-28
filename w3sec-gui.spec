from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH)
SRC = ROOT / "src"
hiddenimports = collect_submodules("w3sec") + ["w3sec.audit"]
datas = [(str(ROOT / "backgrounds" / "atlas_forest.jpg"), "backgrounds")]

a = Analysis([str(ROOT / "w3sec_gui_entry.py")], pathex=[str(SRC)], binaries=[], datas=datas, hiddenimports=hiddenimports,
             hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="ATLAS", debug=False,
          bootloader_ignore_signals=False, strip=False, upx=True, console=False,
          disable_windowed_traceback=False, argv_emulation=False)
