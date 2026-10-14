"""SocksIP entry point for the unified engine."""
from scripts.entrypoint import entrypoint
run, main = entrypoint("sip")
if __name__ == "__main__":
    raise SystemExit(main())
