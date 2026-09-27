from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH)
SRC = ROOT / "src"
hiddenimports = collect_submodules("w3sec")

a = Analysis([str(ROOT / "w3sec_gui_entry.py")], pathex=[str(SRC)], binaries=[], datas=[], hiddenimports=hiddenimports,
             hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="w3sec", debug=False,
          bootloader_ignore_signals=False, strip=False, upx=True, console=False,
          disable_windowed_traceback=False, argv_emulation=False)
