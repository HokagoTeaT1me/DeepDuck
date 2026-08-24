from .command import CommandRunner

__all__ = ["CommandRunner"]


def __getattr__(name):
    if name == "GhidraRuntime":
        from .ghidra import GhidraRuntime

        return GhidraRuntime
    raise AttributeError(name)
