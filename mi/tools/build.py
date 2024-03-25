import subprocess
import sys

if __name__ == "__main__":
    subprocess.check_call(
        [sys.executable, "-m", "tools.gen", "-o", "mi/challenge.pkl.zst"]
    )
