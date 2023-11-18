import sys
import os
import concurrent.futures
import traceback
import errno

import tkinter as tk
import tkinter.messagebox
import tkinter.scrolledtext
import tkinter.filedialog
import tkinter.ttk
import tkinter.font

from multiprocessing import freeze_support
from threading import Lock
from pathlib import Path
from webbrowser import open as open_page
from shutil import disk_usage
from platform import machine
from collections import deque
from time import sleep
from subprocess import list2cmdline

from patcher import patcher
from patcher.version import VERSION
from patcher.patcher import CallbackType as ct

from gui.utils import is_in_temp, is_in_system
from gui.widgets import *

ICON = (
    "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABmJLR0QA/wD/AP+gvaeTAAAAs"
    "UlEQVRYw+1X2w2AIAzsGdZhJYdzJQeqXxCj0ACptj76WZJyXO+ggJnJMiYyjm4AABgAu2NgFJ"
    "h5C1AToSbNRETMjGYGtDeXagYR9bqcC8W5uFbL79dcaiB097JwwlsBaAPzZUNJ/SMnlMSXbOn"
    "zIkpMaAkuW7RwGT3vNXwdgKwBCwf8LnjoTBhnsb92M+EgMN8i1I5mEdYGyCuGUvR+zbJFDwVr"
    "efcaCFpUqn9MPvMabhZfZkN3z2FkAAAAAElFTkSuQmCC"
)


if getattr(sys, 'frozen', False):
    os.chdir(os.path.dirname(sys.executable))
elif __file__:
    os.chdir(os.path.dirname(__file__))


def ensure_executables():
    if os.name == "nt" and getattr(sys, "frozen", False):
        tools = Path(sys._MEIPASS) / "tools"

        # Add tools path to PATH env var so we can use them in `subprocess`.
        new_path = str(tools)
        old_path = os.environ.get("PATH")
        if old_path is not None:
            new_path += f";{old_path}"
        os.environ["PATH"] = new_path

        # Use the 64-bit executable on 64-bit Windows, 32-bit one otherwise.
        arch = "-x" + "64" if machine().endswith("64") else "86"
        (tools / f"xdelta3{arch}.exe").rename(tools / "xdelta3.exe")


class PatcherGUI:
    def __init__(self, root, executor, args):
        self._args = args
        self._jobs = []
        self.patcher = patcher.Patcher(
            self.ask_question, callback=self.callback
        )
        self.title = f"{self.patcher.NAME} v{VERSION}"
        self.root = root
        self.executor = executor
        self.lock = Lock()
        self.callback_queue = deque()
        self._gui_initiated = False

        self.root.protocol("WM_DELETE_WINDOW", self.quit)
        self.root.report_callback_exception = self.report_callback_exception
        self.root.iconphoto(True, tk.PhotoImage(data=ICON))
        self.root.title(self.title)

        self.root.after(0, self.init)

    def report_callback_exception(self, exc_type, exc_value, exc_traceback):
        if isinstance(exc_value, MemoryError):
            exc_value = patcher.PatcherError(
                "Memory error. This could be caused by your anti-virus messing with"
                " this program, this could be caused by bad RAM. So reboot your"
                " PC, close all programs, disable your anti-virus and try again."
            )

        if len(self.callback_queue) > 0:
            self.root.after(
                100, self.report_callback_exception, exc_type, exc_value, exc_traceback
            )
            return

        self.disable()
        more = "Press OK for more information."

        if isinstance(exc_value, patcher.ExitingError):
            pass
        elif isinstance(exc_value, patcher.PatcherError):
            self.callback(
                None,
                "\nCRITICAL ERROR\n",
                "critical",
                f"{exc_value.args[0]}\n",
                "",
                "\nCRITICAL ERROR",
                "critical",
                force_scroll=True,
            )
            tk.messagebox.showerror(
                "Error",
                f"Patcher encountered a critical error and cannot continue. {more}",
            )
        else:
            message = "".join(
                traceback.format_exception(exc_type, exc_value, exc_traceback)
            )

            # in case of unhandled exception make sure patcher cleans up after itself
            self.run(self.patcher.shutdown, self.pass_)

            if self._gui_initiated:
                self.callback(
                    None,
                    "\nUNCAUGHT EXCEPTION\n",
                    "critical",
                    f"{message}\n",
                    "",
                    "UNCAUGHT EXCEPTION",
                    "critical",
                    force_scroll=True,
                )

            tk.messagebox.showerror(
                "Error", f"Uncaught exception. {more}"
            )

            if not self._gui_initiated:
                tk.messagebox.showerror("Error", message)
                self.quit()

    def log_message(self, *args, overwrite=False, append=False, force_scroll=False):
        self.log.config(state="normal")
        scroll = self.log.yview()[1] == 1.0

        if overwrite and not self.patcher.exiting.is_set():
            self.log.delete("end -2l", "end -1l")
        elif append:
            self.log.delete("end -1c", "end")
        self.log.insert("end", *args)

        self.log.insert("end", "\n")
        if scroll or force_scroll:
            self.log.see("end")
        self.log.config(state="disabled")
        self.log.update()

    def _callback(self, callback_type, *args, **kwargs):
        if callback_type is None:
            self.log_message(*args, **kwargs)
        elif callback_type == ct.HEADER:
            self.log_message(f"\n{args[0]}", "header", **kwargs)
        elif callback_type == ct.INFO:
            self.log_message(args[0], **kwargs)
        elif callback_type == ct.FAILURE:
            self.log_message(f" {args[0]}", "critical", append=True, **kwargs)
        elif callback_type == ct.FINISHED:
            self.log_message("\n", "", "All done!", "finished", **kwargs)
        elif callback_type == ct.WARNING:
            self.log_message(f"\n{args[0]}\n", "red", **kwargs)
        elif callback_type == ct.PROGRESS:
            self.set_progress(*args)

    def callback_queue_handler(self):
        while True:
            try:
                args, kwargs = self.callback_queue.popleft()
            except IndexError:
                break

            self._callback(*args, **kwargs)

        self.root.after(100, self.callback_queue_handler)

    def callback(self, *args, wait=False, **kwargs):
        self.callback_queue.append((args, kwargs))

    def ask_question(self, question):
        return tk.messagebox.askyesno("Question", question)

    def center(self):
        self.root.eval("tk::PlaceWindow . center")
        self.root.update_idletasks()

    def init(self):
        self.root.grid_columnconfigure(0, weight=1)

        self.log = tk.scrolledtext.ScrolledText(
            self.root,
            wrap=tk.WORD,
            height=10,
            width=90,
            borderwidth=0,
            highlightthickness=1,
            highlightbackground="#7a7a7a",
            highlightcolor="#7a7a7a",
            state="disabled",
        )
        # font_name = self.log.cget("font")
        font_name = "TkDefaultFont"

        default_font = tk.font.Font(self.log, font_name)
        default_font.config(size="8")

        self.log.config(font=default_font)
        self.log.grid(row=3, column=0, columnspan=2, sticky="we", padx=10, pady=10)

        bold_font = tk.font.Font(self.log, font_name)
        bold_font.config(weight="bold", size="8")

        self.log.tag_config("header", font=bold_font)
        self.log.tag_config("red", foreground="red", font=bold_font)

        big_font = tk.font.Font(self.log, font_name)
        big_font.config(weight="bold", size="12")

        self.log.tag_config("critical", foreground="red", font=big_font)
        self.log.tag_config("finished", foreground="green", font=big_font)

        self.root.resizable(False, False)
        self.root.deiconify()
        self.center()

        self.root.after(0, self.callback_queue_handler)

        self._gui_initiated = True

        self.callback(None, "Initializing...")

        # do it here so we can catch exceptions
        ensure_executables()

        error = None
        if is_in_temp():
            error = (
                "This program can't run from a temporary folder!\n\nIf you downloaded "
                "an archive - extract it first:\nRight click on the downloaded file "
                "> Extract All..."
            )
        if is_in_system():
            error = "Don't run this program from the Windows folder!"
        if error is not None:
            self.callback(
                None,
                "\nCRITICAL ERROR\n",
                "critical",
                f"error\n",
                "",
                "\nCRITICAL ERROR",
                "critical",
                force_scroll=True,
            )
            return

        self.run(self.patcher.load_all_metadata, self.init_1)

    def init_1(self, future):
        games = future.result()

        games_count = len(games)
        if (game := self._args.game) is not None:
            pass
        elif games_count == 1:
            game = games[0]
        elif games_count > 1:
            game = SelectDialog(
                self.root,
                games,
                title="Select game",
                label="Select the game you want to patch:",
                minwidth=250,
            ).result

            if game is None:
                return self.quit()

        self.title += f" for {game}"
        self.root.title(self.title)

        self.run(self.patcher.pick_game, self.init_2, game, args=[game])

    def init_2(self, future, game):
        versions, dlcs, languages, path = future.result()

        if (language := self._args.language) is not None:
            self.patcher.select_language(language)
        elif len(languages) > 0:
            language = SelectDialog(
                self.root,
                languages,
                current="English",
                title="Select language",
                label="Select your game language:",
                minwidth=250,
            ).result

            if language is None:
                return self.quit()

            self.patcher.select_language(language)

        button_name = "Patch"
        if versions is None:
            button_name = "Install DLCs"
        else:
            self.title += f" - from {versions[0]} to {versions[1]}"
        if dlcs > 0:
            self.title += f" (+{dlcs} DLCs)"
        self.root.title(self.title)

        tk.ttk.Label(self.root, text=f"Select folder with {game}:").grid(
            row=0, column=0, sticky="w", columnspan=2, padx=10, pady=(8, 0)
        )
        self.game_path = tk.StringVar(value=fr"D:\Games\{game}")

        if path is not None:
            self.game_path.set(path)

        self.path_entry = tk.ttk.Entry(self.root, textvariable=self.game_path)
        self.path_entry.grid(row=1, column=0, sticky="we", padx=(10, 5), pady=(0, 10))
        self.browse_button = tk.ttk.Button(
            self.root, text="Browse...", command=self.browse_folder
        )
        self.browse_button.grid(
            row=1, column=1, sticky="we", padx=(5, 10), pady=(0, 10)
        )

        self.progressbar = tk.ttk.Progressbar(self.root)
        self.progressbar.grid(row=2, column=0, sticky="we", columnspan=2, padx=10)
        self.progressbar.grid_remove()

        self.root.rowconfigure(2, minsize=26)
        self.patch_button = tk.ttk.Button(
            self.root, text=button_name, command=self.patch
        )
        self.patch_button.grid(row=2, column=0, sticky="we", columnspan=2, padx=10)

        self.center()

        if (game_dir := self._args.dir) is not None:
            self.game_path.set(game_dir)
            self.patch()

    def browse_folder(self):
        try:
            folder = tk.filedialog.askdirectory()
        except tk.TclError:
            tk.messagebox.showerror(
                "Error",
                "Something went wrong, can't browse the folder.\n"
                "Try again or enter the path manually."
            )
            return

        if folder != "":
            try:
                folder = str(Path(folder).resolve())
            except OSError:
                tk.messagebox.showerror("Error", "Bad folder selected")
            else:
                self.game_path.set(folder)

    def set_progress(self, current, maximum):
        # self.progressbar["mode"] = "indeterminate"
        self.progressbar["mode"] = "determinate"
        self.progressbar.stop()
        self.progressbar.configure(value=current, maximum=maximum)

    def patch(self):
        self.path_entry.configure(state="disable")
        self.browse_button.configure(state="disable")

        self.patch_button.grid_remove()
        self.progressbar.grid()

        self.progressbar["mode"] = "determinate"
        self.progressbar.configure(value=0, maximum=100)
        self.progressbar.start()

        self.run(self.patcher.check_files_quick, self.patch_1, self.game_path.get())

    def abort_patching(self):
        self.path_entry.configure(state="enable")
        self.browse_button.configure(state="enable")
        self.progressbar.grid_remove()
        self.patch_button.grid()

    def patch_1(self, future):
        try:
            all_dlcs, missing_dlcs = future.result()
        except patcher.FileMissingError as e:
            self.callback(None, f"\n{e.args[0]}", "red", force_scroll=True)

            self.abort_patching()
            return

        if self._args.dlcs:
            if (selected_dlcs := self._args.dlc) is not None:
                pass
            else:
                selected_dlcs = ()
        elif len(all_dlcs) > 0:
            indices = CheckDialog(
                self.root,
                all_dlcs,
                checked=missing_dlcs,
                title="Extract DLCs",
                label="Select DLCs you want to extract:",
                minwidth=250,
            ).result
            if indices is None:
                self.abort_patching()
                return

            selected_dlcs = tuple(all_dlcs[i] for i in indices)
        else:
            selected_dlcs = ()

        self.run(self.patcher.patch, self.patch_2, selected_dlcs)

    def patch_2(self, future):
        try:
            future.result()
        except patcher.WritePermissionError as e:
            if os.name != "nt":
                raise patcher.PatcherError(
                    "Can't move files to your game folder. "
                    "Try running this script with elevated permissions."
                )
            elif self._args.admin:
                raise patcher.PatcherError(
                    "Can't finish despite running as administrator. "
                    f"Original error message:\n\n{e.args[0]}"
                )
            else:
                try:
                    import subprocess

                    import pywintypes

                    from win32com.shell import shell
                except ImportError:
                    raise patcher.PatcherError(
                        "Can't move files to your game folder.\n"
                        "Try running this program as administrator."
                    )

                args = [
                    "--admin",
                    "--game",
                    self.patcher._game_name,
                    "--dir",
                    self.patcher._game_dir,
                    "--dlcs",
                ]
                if (language := self.patcher._language) is not None:
                    args.append("--language")
                    args.append(language)
                for dlc in self.patcher._selected_dlcs:
                    args.append("--dlc")
                    args.append(dlc)
                if not getattr(sys, "frozen", False):
                    args.insert(0, sys.argv[0])

                try:
                    shell.ShellExecuteEx(
                        lpVerb="runas",
                        lpFile=sys.executable,
                        lpParameters=list2cmdline(args),
                    )
                except pywintypes.error as e:
                    if e.winerror == 1223:  # winerror.ERROR_CANCELLED:
                        game = fr"D:\Games\{self.patcher._game_name}"
                        raise patcher.PatcherError(
                            "Can't move files to your game folder.\nIf you "
                            "don't have administrator rights - copy your "
                            f'game somewhere else, for example:\n"{game}"'
                        )
                    raise
                sys.exit(0)

    def pass_(self, future):
        future.result()

    """
    Don't ask me about the code below. It definitely can be done better way.
    This is what I came up with when making the first version of Sims 4 Updater.
    If it ain't broke, don't fix it.
    """

    def check_future(self, future, run_after, *args, **kwargs):
        with self.lock:
            if future.done():
                self._jobs.remove(future)
                # If it's set then `future` raises `ExitingError` or something else.
                # If it does `None` in the job list will abort exiting.
                if self.patcher.exiting.is_set():
                    self._jobs.append(None)
                    try:
                        future.result()
                    except patcher.ExitingError:
                        pass
                    self._jobs.remove(None)
                    return
                self.root.after(0, run_after, future, *args, **kwargs)
            else:
                self.root.after(
                    100, self.check_future, future, run_after, *args, **kwargs
                )

    def run(self, function, run_after, *args_, args=None, kwargs=None, **kwargs_):
        future = self.executor.submit(function, *args_, **kwargs_)
        with self.lock:
            self._jobs.append(future)
        if args is None:
            args = []
        if kwargs is None:
            kwargs = {}
        self.check_future(future, run_after, *args, **kwargs)

    def disable(self):
        for child in self.root.winfo_children():
            if isinstance(child, tk.ttk.Progressbar):
                child.stop()
            else:
                try:
                    child.configure(state="disable")
                except tk.TclError:
                    pass

    def _quit(self):
        with self.lock:
            if len(self._jobs) > 0:
                # True if there was some unhandled exception when exiting.
                # In that case abort the exit so the user can read it.
                if None in self._jobs:
                    self._jobs.remove(None)
                    return
                self.root.after(100, self._quit)
            else:
                self.root.destroy()

    def quit(self):
        self.callback(None, "Exiting on user's request...")
        self.patcher.exiting.set()
        self.disable()
        self._quit()


def main():
    import argparse

    parser = argparse.ArgumentParser()
    # I don't care if people run the Patcher themselves with this flag, it's their
    # fault. If it's set the Patcher will fail if there are any errors when moving
    # files to the game folder. If it's not set it reruns itself as admin.
    parser.add_argument("--admin", action="store_true")
    parser.add_argument("--game", default=None)
    parser.add_argument("--language", default=None)
    parser.add_argument("--dir", default=None)
    parser.add_argument("--dlcs", action="store_true")
    parser.add_argument("--dlc", action="append", default=None)
    args, _ = parser.parse_known_intermixed_args()

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        root = tk.Tk()
        root.withdraw()
        app = PatcherGUI(root, executor, args)
        root.mainloop()


if __name__ == "__main__":
    freeze_support()
    main()
