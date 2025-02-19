#!/bin/bash
cd "$(dirname "$0")"
echo "Starting Endec..."

# Check if venv exists, if not create it
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Creating..."
    python3 -m venv venv
    source venv/bin/activate
    echo "Installing dependencies..."
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

python3 endec.py
