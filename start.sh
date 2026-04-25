#!/bin/bash
set -e
echo "Starting SENTINEL..."

# Check Ollama (non-blocking)
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "Ollama detected and running"
else
    echo "Warning: Ollama not detected — LLM features will use fallback mode"
fi

pip install -r requirements.txt -q
python seed.py

echo "SENTINEL at http://localhost:8000"
echo "API docs at http://localhost:8000/docs"
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
