# SNS Message Validator

A Django-based API utility to validate AWS SNS (Simple Notification Service) messages using public/private key signatures.

This project uses Django REST Framework, the `cryptography` library, and `requests` to ensure the authenticity of SNS messages through digital signature verification.

## Installation Guide (macOS/Linux)

Create a virtual environment to isolate your package dependencies locally:

1. Create virtual environment and activate it
   ```bash
   python3 -m venv env
   source env/bin/activate
3. Install packages
   ```bash
   pip install djangorestframework cryptography requests
