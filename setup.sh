#!/bin/bash
echo "Setting up TRACEX environment..."

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

echo ""
echo "Done. Run with:"
echo "  source .venv/bin/activate"
echo "  pip install -e ."
echo "  tracex yourfile.evtx"
echo "  tracex --help for more options"