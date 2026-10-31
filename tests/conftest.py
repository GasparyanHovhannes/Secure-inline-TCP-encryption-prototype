import os
import sys

# Works with old pytest (Ubuntu 22.04 ships 6.x, which has no "pythonpath" ini option).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
