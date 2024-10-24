@echo off
python -m PyInstaller ^
    --noupx ^
    --noconfirm ^
    --log-level=WARN ^
    --onefile ^
    --noconsole ^
    --clean ^
    --name patcher ^
    --icon icon.ico ^
    --add-binary tools\*;tools ^
    --add-data tools\*.txt;tools ^
    patcher_gui.py

REM python -m PyInstaller --noupx --noconfirm --log-level=WARN --onefile --nowindow --clean --name patcher --noconsole --icon icon.ico patcher_gui.py
rmdir /s /q build
del patcher.spec
