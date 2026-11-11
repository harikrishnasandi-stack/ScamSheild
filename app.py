"""
ScamShield 2.0 - Root Deployment Entrypoint.
Enables instant deployment on Streamlit Community Cloud, Render, and Hugging Face Spaces
regardless of whether the deployer specifies the root or subfolder path.
"""

import os
import sys

# Add inner folder to module search path and set working directory
current_dir = os.path.dirname(os.path.abspath(__file__))
sub_dir = os.path.join(current_dir, "scamshield-2.0-main")

if os.path.isdir(sub_dir):
    if sub_dir not in sys.path:
        sys.path.insert(0, sub_dir)
    os.chdir(sub_dir)
    target_app = os.path.join(sub_dir, "app.py")
else:
    target_app = os.path.join(current_dir, "app.py")

with open(target_app, "r", encoding="utf-8") as f:
    code = f.read()

exec(code, globals())
