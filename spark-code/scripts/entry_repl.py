# PyInstaller entry: the console REPL exe (spark-code.exe).
import sys

from spark_code.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
