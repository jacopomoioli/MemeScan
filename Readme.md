# MemeScan
A simple user mode memory scanner, that searches for suspicious memory pages by leveraging `VirtualQueryEx`.

## ToDo
- Use bitwise on protection constants
- Test single process analysis
- Free the memory of WTSEnumerateProcesses using WTSFreeMemory (as the [doc](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumerateprocessesa) says)
- Add check to highlight non-backed RWX pages 
- Add check to MEM_IMAGE pages without related file
- Use SeDebugPrivilege to check system processes
- Test with x86 proesses
- Dump suspicious memory to file for further analysis


## Usage
### Single process scan
```bash
.\memescan.exe <pid>
```

### System wide scan
```bash
.\memescan.exe
```
