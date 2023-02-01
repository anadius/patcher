# Patcher and Patch Maker

Programs for making patches and updating stuff with them. Patch Maker expects `xdelta3` in your PATH. Patcher comes with its own. Main (and only?) advantage of this Patcher is that you can apply multiple patches at once, which should save your time. Some files can be set as optional - if Patcher fails to update them it can still continue the process. Some files can be set as language files - you select which language you play in; files for other languages are considered optional - so again, if Patcher fails to update them it continues anyway.

I made the Patcher as a base for my Sims 4 Updater. If you see something weird in the code - it's probably to make it easier to build Updater on top of it.

Patch maker CLI doesn't expose all functionality of patch maker script but I don't think that's necessary. Some of it is used by Updater only and not the Patcher (like packing base game files, full patch, extra files), some of it doesn't make sense for most games (packing DLCs separately - they are often included in base game files; and if they are not, you want all DLCs anyway, so include them in patch).

I consider it good enough, I don't plan to make any changes. I know it's inconsistent that Patcher is GUI and Patch Maker is CLI but I have no intention of making their counterparts.

### FAQ:

    Q: Patcher doesn't run, I get some error message, what should I do?
    A: First of all the Patcher exe is 64-bit only, so make sure your Windows
       is 64-bit too. It's written in Python 3.10 and they dropped Windows 7
       support in 3.9, so if you have Windows 7 - update it to 8 or newer.
       And lastly make sure you have VC Redist 2015-2022 x64
       ( https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads )
       installed and that your anti-virus doesn't block it.
       If your system is 32-bit you can run it from source code.
       If you're on Windows 7 you can try running it from source code too,
       using older version of Python, but don't expect any support.

    Q: I get some error, doing what error message says doesn't help, what should I do?
    A: First culprit is your anti-virus. Disable it.
       If that doesn't help reset file permissions (see question below).
       If that doesn't help copy the Patcher and patch files somewhere else.
           That's important: COPY, not move.
       If that doesn't help copy your game somewhere else.
           Again: COPY, not move.

    Q: Error message tells me to reset file permissions, how do I do it?
    A: Download this file
       ( https://anadius.hermietkreeft.site/attachments/reset-folder-permissions.bat )
       ( https://cdn.discordapp.com/attachments/975718723367338015/975719718101086298/reset-folder-permissions.bat )
       Right click on it, run as administrator.
