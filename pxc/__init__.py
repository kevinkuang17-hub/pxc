import os

_here = os.path.dirname(os.path.abspath(__file__))


def _read_version():
    for p in (os.path.join(_here, "VERSION"), os.path.join(_here, "..", "VERSION")):
        try:
            with open(p) as f:
                return f.read().strip()
        except OSError:
            continue
    return "v0.0.0-dev"


__version__ = _read_version()


def _read_build():
    try:
        with open(os.path.join(_here, "BUILD")) as f:
            return f.read().strip()
    except OSError:
        return ""


__build__ = _read_build()
