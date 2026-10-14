"""V2Box entry point for the unified engine."""
from scripts.entrypoint import entrypoint
run, main = entrypoint("v2box")
if __name__ == "__main__":
    raise SystemExit(main())
