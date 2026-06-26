@echo off
echo Installing TRACEX dependencies...
pip install -r requirements.txt
echo pip install -e .
echo Done. Run with: tracex yourfile.evtx
echo tracex --help for more options
pause