"""Historical filenames expose the same single engine, not old implementations."""
from .unified_cli import main as unified_main, run_bytes


def entrypoint(suffix):
    def run(data, password=None, *, hwid=None, suffix_override=None):
        return run_bytes(data, suffix_override or suffix, password=password, hwid=hwid)

    def main(argv=None):
        return unified_main(argv, default_suffix=suffix)

    return run, main
