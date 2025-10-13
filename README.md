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
