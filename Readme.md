# MemeScan
A simple user mode memory scanner, that searches for suspicious memory pages by leveraging `VirtualQueryEx`.

## Usage
### Single process scan
```bash
.\memescan.exe <pid>
```

### System wide scan
```bash
.\memescan.exe
```