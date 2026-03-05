<<<<<<< HEAD
# Advanced Steganography App

Quick start:

1. Create & activate the virtual environment (if you don't have one):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
python -m pip install -r backend/requirements.txt
```

3. Start the app (recommended):

```bash
./run.sh
```

Or start directly with the venv Python:

```bash
.venv/bin/python backend/app.py
```

Health check:

```bash
curl http://localhost:5000/api/health
```

If you see `ModuleNotFoundError: No module named 'flask'`, make sure you installed dependencies into the `.venv` (step 2) and that you're using the venv's Python to run the app.
=======
# StegoPy — Encrypted Image Steganography

## Overview
StegoPy hides encrypted messages inside images using LSB steganography with password-based encryption.

## Objectives
- Implement data hiding using LSB
- Add encryption for message security
- Provide a simple CLI interface
- Ensure image integrity

## Example Commands
```bash
python stego.py embed input.png output.png "My secret message" "MyPassword"
python stego.py extract output.png "MyPassword"
>>>>>>> f7b04b05d356498f9b35800461d92942e928748b

