@echo off
echo Setting up TRACEX...
pip install -r requirements.txt
pip install -e .
echo.
echo Done. Run with: tracex yourfile.evtx
pause
