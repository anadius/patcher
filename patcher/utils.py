__all__ = ["parse_size"]

_UNITS = {
    b"B": 1,
    b"KiB": 1024,
    b"MiB": 1048576,
    b"GiB": 1073741824,
}


def parse_size(size, unit):
    return float(size) * _UNITS[unit]
