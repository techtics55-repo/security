import sys
import os

app_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(app_dir))

from agent_app.__main__ import main

if __name__ == "__main__":
    main()
