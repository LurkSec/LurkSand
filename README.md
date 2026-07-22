# LurkSand PE Binary Header & Behavioral Malware Sandbox

LurkSand parses Portable Executable (PE) headers, calculates binary entropy for packer/encryption detection, and audits suspicious Win32 API imports.

## Features
- PE Header Parsing & Entropy: Measures Shannon entropy to detect packed or encrypted payloads.
- API Import Auditing: Flags process injection and memory manipulation calls (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`).
- Behavioral Verdicts: Assigns threat scores and verdicts (`MALICIOUS`, `SUSPICIOUS`, `BENIGN`).

## Usage

### Run Local Engine & Web Dashboard (Port 8015)
```bash
python lurksand.py serve --port 8015
```

### Run CLI Sandbox Audit
```bash
python lurksand.py audit
```

## License
MIT License. Created by Lurk (LurkSec).
