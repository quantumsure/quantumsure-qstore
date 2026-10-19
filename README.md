# quantumsure-qstore

Quantum-resistant field-level encryption for client data.

Encrypt sensitive fields **before** they are written to your database.  
Decrypt them only when you need the plaintext.  
The plaintext never leaves your environment.

Powered by **ML-KEM-1024** (Kyber) + **ChaCha20-Poly1305**.

## Installation

```bash
npm install quantumsure-qstore
