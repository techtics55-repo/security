@echo off
cd /d "C:\Users\shrey\OneDrive\Desktop\New folder\security"
start /B "" "C:\Users\shrey\OneDrive\Desktop\New folder\security\.venv\Scripts\python.exe" -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
echo Aegis server starting on http://localhost:8000
