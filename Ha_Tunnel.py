"""HAT entry point for the unified engine."""
from scripts.entrypoint import entrypoint
run, main = entrypoint("hat")
if __name__ == "__main__":
    raise SystemExit(main())
