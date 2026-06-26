#!/bin/bash
echo "Setting up TRACEX..."
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
echo ""
echo "Done. Activate venv and run with:"
echo "  source .venv/bin/activate"
echo "  tracex yourfile.evtx"
