@echo off
start /B "" "C:\Users\shrey\OneDrive\Desktop\New folder\security\.venv\Scripts\python.exe" -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
