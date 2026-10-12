"""`python -m proveit_mcp` et le script console `proveit-mcp` : le serveur MCP en stdio."""

import sys

from proveit_mcp import __version__, serveur


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--version"]:
        print(__version__)
        return 0
    return serveur.lancer()


if __name__ == "__main__":
    sys.exit(main())
