"""NPV entry point for the unified engine; CLI infers npvt/npv4/npvs."""
from scripts.entrypoint import entrypoint
run, main = entrypoint("npvt")
if __name__ == "__main__":
    raise SystemExit(main())
