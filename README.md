# pyelfinject

Inject arbitrary code into an ELF file.

Assemble hello.s with:
```
nasm -f bin -o hello.bin hello.s
```
  
Target binary must be compiled non position-independent (-no-pie flag)
