"""HTTP Custom entry point for the unified engine."""
from scripts.entrypoint import entrypoint
run, main = entrypoint("hc")
if __name__ == "__main__":
    raise SystemExit(main())
