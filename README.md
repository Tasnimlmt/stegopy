# StegoPy — Encrypted Image Steganography

## Overview

StegoPy is a steganography application that hides encrypted messages inside images using **LSB (Least Significant Bit) steganography** combined with password-based encryption.

The project allows users to securely embed and extract hidden messages from images while maintaining image integrity.

---

## Objectives

* Implement data hiding using **LSB steganography**
* Add **encryption** to secure hidden messages
* Provide a **simple interface** for embedding and extracting data
* Maintain **image quality and integrity**

---

## Quick Start

### 1. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
python -m pip install -r backend/requirements.txt
```

### 3. Start the application

Recommended method:

```bash
./run.sh
```

Or run directly with the virtual environment Python:

```bash
.venv/bin/python backend/app.py
```

---

## Health Check

```bash
curl http://localhost:5000/api/health
```

---

## Example CLI Commands

Embed a message inside an image:

```bash
python stego.py embed input.png output.png "My secret message" "MyPassword"
```

Extract a hidden message:

```bash
python stego.py extract output.png "MyPassword"
```

---

## Troubleshooting

If you see the error:

```
ModuleNotFoundError: No module named 'flask'
```

Make sure:

1. Dependencies were installed using the virtual environment.
2. The application is executed using the `.venv` Python interpreter.

