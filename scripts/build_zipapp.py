import zipapp
import os
import shutil
import tempfile

tmpdir = os.path.join(tempfile.gettempdir(), "aegis_cli_build")
if os.path.exists(tmpdir):
    shutil.rmtree(tmpdir, ignore_errors=True)
os.makedirs(tmpdir, exist_ok=True)

base = r"C:\Users\shrey\OneDrive\Desktop\New folder\security"

# Copy agent_app module
shutil.copytree(os.path.join(base, "agent_app"), os.path.join(tmpdir, "agent_app"), dirs_exist_ok=True)
# Remove pycache
for root, dirs, files in os.walk(tmpdir):
    for d in dirs:
        if d == "__pycache__":
            shutil.rmtree(os.path.join(root, d), ignore_errors=True)

# Copy backend module
shutil.copytree(os.path.join(base, "backend"), os.path.join(tmpdir, "backend"), dirs_exist_ok=True)
for root, dirs, files in os.walk(tmpdir):
    for d in dirs:
        if d == "__pycache__":
            shutil.rmtree(os.path.join(root, d), ignore_errors=True)

# Make sure backend has __init__.py
init_file = os.path.join(tmpdir, "backend", "__init__.py")
if not os.path.exists(init_file):
    with open(init_file, "w") as f:
        f.write("")

# Create __main__.py
main_file = os.path.join(tmpdir, "__main__.py")
with open(main_file, "w") as f:
    f.write("import sys\nsys.path.insert(0, '.')\nfrom agent_app.cli import main\nmain()\n")

# Build zipapp
output = os.path.join(base, "downloads", "aegis-cli.pyz")
zipapp.create_archive(tmpdir, output, interpreter="/usr/bin/env python3")
print(f"Created {output} ({os.path.getsize(output)} bytes)")

shutil.rmtree(tmpdir, ignore_errors=True)
