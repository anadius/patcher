import sys
import os
import subprocess
import signal
import threading
import time

__all__ = ["Popen2"]


if os.name == "nt":
    import ctypes
    from multiprocessing import Process


    def ctrlc(pid):
        kernel = ctypes.windll.kernel32
        kernel.FreeConsole()
        kernel.AttachConsole(pid)
        kernel.SetConsoleCtrlHandler(None, 1)
        kernel.GenerateConsoleCtrlEvent(0, 0)
        sys.exit(0)


def _process_buffer(buf):
    lines = buf.replace(b"\r\n", b"\n").split(b"\n")
    buf = lines.pop()
    return buf, lines


# Why this stuff was needed: https://github.com/anadius/ctrlc
class Popen2(subprocess.Popen):
    def __init__(self, *args, check_exiting=None, **kwargs):
        self._check_exiting = check_exiting

        if os.name == "nt":
            kwargs["creationflags"] = (
                kwargs.get("creationflags", 0) | subprocess.CREATE_NEW_CONSOLE
            )
            startupinfo = kwargs.get("startupinfo", subprocess.STARTUPINFO())
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            kwargs["startupinfo"] = startupinfo

        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
        kwargs["stdin"] = subprocess.PIPE

        super().__init__(*args, **kwargs)

    def interrupt(self):
        if os.name == "nt":  # Windows
            try:
                p = Process(target=ctrlc, args=(self.pid, ))
                p.start()
            except Exception as e:
                self.terminate()
                self.wait()

                if isinstance(e, FileNotFoundError) or isinstance(e, PermissionError):
                    return self.wait()

                raise

            watchdog = threading.Timer(10, p.terminate)
            watchdog.start()
            p.join()
            watchdog.cancel()

        else:  # Linux or Mac
            self.send_signal(signal.SIGINT)

        watchdog = threading.Timer(10, self.terminate)
        watchdog.start()
        exitcode = self.wait()
        watchdog.cancel()

        return exitcode

    def lines(self, stderr=False):
        if stderr:
            source = self.stderr
        else:
            source = self.stdout

        buf = b""
        while self.poll() is None:
            buf += source.read(len(source.peek()))
            buf, lines = _process_buffer(buf)
            yield from lines

            if self._check_exiting is not None:
                self._check_exiting()

            time.sleep(0.1)

        buf += source.read()
        buf, lines = _process_buffer(buf)
        yield from lines

    def running(self, seconds=0.1):
        nanoseconds = seconds * (10 ** 9)
        start = time.time_ns()
        while self.poll() is None and time.time_ns() - start < nanoseconds:
            if self._check_exiting is not None:
                self._check_exiting()
            time.sleep(0.1)

        return self.poll() is None
