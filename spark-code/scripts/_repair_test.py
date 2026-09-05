import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from spark_code.protocol import ToolStreamFilter


def run(block):
    f = ToolStreamFilter()
    f.feed('