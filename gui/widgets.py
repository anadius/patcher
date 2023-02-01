import tkinter as tk
import tkinter.ttk
import tkinter.simpledialog

from webbrowser import open_new as open_url

__all__ = ["Dialog", "Link", "SelectDialog", "CheckDialog"]


class Dialog(tk.simpledialog.Dialog):
    def __init__(
        self,
        parent,
        title=None,
        label=None,
        extra_buttons=None,
        resizable=None,
        minwidth=None,
    ):
        self._result = None
        self._label = label
        self._extra_buttons = [] if extra_buttons is None else extra_buttons
        self._resizable = (False, False) if resizable is None else resizable
        self._minwidth = minwidth

        super().__init__(parent, title)

    def body(self, parent):
        """
        Don't touch this one, override `self.content` instead!
        """
        self._body = parent

        parent.grid_columnconfigure(0, weight=1)
        if self._minwidth is not None:
            parent.grid_columnconfigure(0, minsize=self._minwidth)

        tk.ttk.Style().configure("PatcherDialog.TLabel", background="white")

        if self._label is not None:
            lbl = tk.ttk.Label(
                parent,
                text=self._label,
                anchor="w",
                justify="left",
                style="PatcherDialog.TLabel",
            )
            lbl.grid(sticky="we", padx=10, pady=(10, 0))

            pad_top = 0
        else:
            pad_top = 10

        inner_body = tk.Frame(parent, bg="white")
        inner_body.grid(sticky="we", padx=10, pady=(pad_top, 10))

        self.content(inner_body)

    def content(self, parent):
        """
        Override this one, not `self.body`!
        """
        pass

    def custom_button(self, value):
        self._result = value
        self.ok()

    def buttonbox(self):
        # Hacky but I don"t want to copy-paste `__init__`
        self.resizable(*self._resizable)
        self._body.config(bg="white")
        self._body.pack(fill="x", padx=0, pady=0)

        box = tk.Frame(self)

        w = tk.ttk.Button(box, text="OK", width=10, command=self.ok, default=tk.ACTIVE)
        w.pack(side=tk.LEFT, padx=5)
        w = tk.ttk.Button(box, text="Cancel", width=10, command=self.cancel)
        w.pack(side=tk.LEFT, padx=5)

        self.bind("<Return>", self.ok)
        self.bind("<Escape>", self.cancel)

        for name, id in self._extra_buttons:
            w = tk.ttk.Button(box, text=name, width=10, command=(lambda x: lambda: self.custom_button(x))(id))
            w.pack(side=tk.LEFT, padx=5)

        box.pack(padx=10, ipady=10, side=tk.RIGHT)

    def apply(self):
        """
        If custom button was pressed `self._result` is set to that button ID.
        If OK was pressed `self._result` is None.
        If Cancel was pressed this method is not called.
        """
        self.result = True if self._result is None else self._result


class Link(tk.Label):
    def __init__(self, parent, text, action):
        super().__init__(parent, text=text, fg="blue", cursor="hand2")
        if isinstance(action, str):
            url = action
            action = lambda e: open_url(url)
        self.bind("<Button-1>", action)


class SelectDialog(Dialog):
    def __init__(self, parent, values, current=None, **kwargs):
        self.values = values
        self.current = current

        super().__init__(parent, **kwargs)

    def content(self, parent):
        parent.grid_columnconfigure(0, weight=1)

        self._cb = tk.ttk.Combobox(parent, width=max(map(lambda x: len(x), self.values)))
        self._cb["values"] = self.values
        self._cb["state"] = "readonly"

        if isinstance(self.current, int):
            current = self.current
        else:
            try:
                current = self.values.index(self.current)
            except ValueError:
                current = 0

        self._cb.current(current)
        self._cb.grid(row=0, column=0, sticky="we")

        return self._cb

    def apply(self):
        self.result = self._cb.get()


class CheckDialog(Dialog):
    """
    Returns indices because values may be duplicated.
    """
    def __init__(self, parent, values, checked=None, **kwargs):
        self.values = values
        self.checked = checked

        super().__init__(parent, **kwargs)

    def content(self, parent):
        parent.grid_columnconfigure(0, weight=1)

        tk.ttk.Style().configure("PatcherDialog.TCheckbutton", background="white")

        self._checkbox_values = []

        if self.checked is None:
            self.checked = []

        in_one_column = 10
        count = len(self.values)
        while count / in_one_column > 4:
            in_one_column += 1

        for i, name in enumerate(self.values):
            checkbox_val = tk.IntVar(value=i if name in self.checked else -1)
            self._checkbox_values.append(checkbox_val)

            checkbox = tk.ttk.Checkbutton(
                parent,
                text=name,
                variable=checkbox_val,
                onvalue=i,
                offvalue=-1,
                style="PatcherDialog.TCheckbutton",
            )
            checkbox.grid(row=1+i%in_one_column, column=i//in_one_column, sticky="w")

    def apply(self):
        result = []
        for checkbox_val in self._checkbox_values:
            value = checkbox_val.get()
            if value != -1:
                result.append(value)

        self.result = result
