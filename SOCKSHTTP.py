"""SocksHTTP entry point for the unified engine."""
from scripts.entrypoint import entrypoint
run, main = entrypoint("sks")
if __name__ == "__main__":
    raise SystemExit(main())
