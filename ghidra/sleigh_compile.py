#!/usr/bin/env python3
import pathlib
import subprocess
import sys


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: sleigh_compile.py <sleighc> <processor-dir> <stamp>", file=sys.stderr)
        return 2

    sleighc, proc_dir, stamp_path = sys.argv[1:4]
    result = subprocess.run([sleighc, "-a", proc_dir], check=False)
    if result.returncode != 0:
        return result.returncode

    pathlib.Path(stamp_path).write_text("ok\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
