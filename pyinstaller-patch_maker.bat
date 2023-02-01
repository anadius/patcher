@echo off
python -m PyInstaller ^
    --noupx ^
    --noconfirm ^
    --log-level=WARN ^
    --onefile ^
    --nowindow ^
    --clean ^
    --name patch_maker ^
    --icon icon.ico ^
    patch_maker_cli.py

rmdir /s /q build
del patch_maker.spec
