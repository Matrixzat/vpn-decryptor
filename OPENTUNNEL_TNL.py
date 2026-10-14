"""OpenTunnel entry point for the unified engine."""
from scripts.entrypoint import entrypoint
run, main = entrypoint("tnl")
if __name__ == "__main__":
    raise SystemExit(main())
