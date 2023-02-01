class UnhandledError(Exception):
    pass


class PatcherError(Exception):
    pass


class ExitingError(PatcherError):
    pass


class NewerPatcherRequiredError(PatcherError):
    pass


class NoPatchesDLCsFoundError(PatcherError):
    pass


class VersionsMissingError(PatcherError):
    pass


class ContinuityError(PatcherError):
    pass


class CrackMissingError(PatcherError):
    pass


class WritePermissionError(PatcherError):
    pass


class DLCPatchesNotImplementedError(PatcherError):
    pass


class DuplicatedDLCsError(PatcherError):
    pass


class FileMissingError(PatcherError):
    pass


class CannotUpdateError(PatcherError):
    pass


class NotEnoughSpaceError(PatcherError):
    pass


class XdeltaError(PatcherError):
    pass


class UnrarError(PatcherError):
    pass


class AVButtinInError(PatcherError):
    pass
