#include "proc.h"
#include "kfirmware.h"

struct proc *proc_find_by_name(const char *name) {
    int pcomm_offset = 0x454;
    if (cached_firmware == 505) {
        pcomm_offset = 0x44C;
    }

    struct proc *p;

    if (!name) {
        return NULL;
    }

    p = *allproc;
    uint64_t currentProc = (uint64_t)*allproc;
    do {
        if (!memcmp((void*)(currentProc + pcomm_offset), name, strlen(name))) {
            return p;
        }
        currentProc = *(uint64_t *)currentProc;
    } while ((p = p->p_forw));

    return NULL;
}

struct proc *proc_find_by_pid(int pid) {
    struct proc *p;

    p = *allproc;
    do {
        if (p->pid == pid) {
            return p;
        }
    } while ((p = p->p_forw));

    return NULL;
}

int proc_get_vm_map(struct proc *p, struct proc_vm_map_entry **entries, uint64_t *num_entries) {
    struct proc_vm_map_entry *info = NULL;
    struct vm_map_entry *entry = NULL;
    int r = 0;

    struct vmspace *vm = p->p_vmspace;
    struct vm_map *map = &vm->vm_map;

    vm_map_lock_read(map);

    int num = map->nentries;
    if (!num) {
        goto error;
    }

    r = vm_map_lookup_entry(map, NULL, &entry);
    if (r) {
        goto error;
    }

    info = (struct proc_vm_map_entry *)malloc(num * sizeof(struct proc_vm_map_entry), M_TEMP, 2);
    if (!info) {
        r = 1;
        goto error;
    }

    for (int i = 0; i < num; i++) {
        info[i].start = entry->start;
        info[i].end = entry->end;
        info[i].offset = entry->offset;
        info[i].prot = entry->prot & (entry->prot >> 8);
        memcpy(info[i].name, entry->name, sizeof(info[i].name));

        if (!(entry = entry->next)) {
            break;
        }
    }

error:
    vm_map_unlock_read(map);

    if (entries) {
        *entries = info;
    }

    if (num_entries) {
        *num_entries = num;
    }

    return 0;
}

int proc_rw_mem(struct proc *p, void *ptr, uint64_t size, void *data, uint64_t *n, int write) {
    struct thread *td = curthread();
    struct iovec iov;
    struct uio uio;
    int r = 0;

    if (!p) {
        return 1;
    }

    if (size == 0) {
        if (n) {
            *n = 0;
        }

        return 0;
    }

    memset(&iov, NULL, sizeof(iov));
    iov.iov_base = (uint64_t)data;
    iov.iov_len = size;

    memset(&uio, NULL, sizeof(uio));
    uio.uio_iov = (uint64_t)&iov;
    uio.uio_iovcnt = 1;
    uio.uio_offset = (uint64_t)ptr;
    uio.uio_resid = (uint64_t)size;
    uio.uio_segflg = UIO_SYSSPACE;
    uio.uio_rw = write ? UIO_WRITE : UIO_READ;
    uio.uio_td = td;

    r = proc_rwmem(p, &uio);

    if (n) {
        *n = (uint64_t)((uint64_t)size - uio.uio_resid);
    }

    return r;
}

inline int proc_read_mem(struct proc *p, void *ptr, uint64_t size, void *data, uint64_t *n) {
    return proc_rw_mem(p, ptr, size, data, n, 0);
}

inline int proc_write_mem(struct proc *p, void *ptr, uint64_t size, void *data, uint64_t *n) {
    return proc_rw_mem(p, ptr, size, data, n, 1);
}

int proc_allocate(struct proc *p, void **address, uint64_t size) {
    uint64_t addr = NULL;
    int r = 0;

    if (!address) {
        r = 1;
        goto error;
    }

    struct vmspace *vm = p->p_vmspace;
    struct vm_map *map = &vm->vm_map;

    vm_map_lock(map);

    r = vm_map_findspace(map, NULL, size, &addr);
    if (r) {
        vm_map_unlock(map);
        goto error;
    }

    r = vm_map_insert(map, NULL, NULL, addr, addr + size, VM_PROT_ALL, VM_PROT_ALL, 0);

    vm_map_unlock(map);

    if (r) {
        goto error;
    }

    if (address) {
        *address = (void *)addr;
    }

error:
    return r;
}

int proc_deallocate(struct proc *p, void *address, uint64_t size) {
    int r = 0;

    struct vmspace *vm = p->p_vmspace;
    struct vm_map *map = &vm->vm_map;

    vm_map_lock(map);

    r = vm_map_delete(map, (uint64_t)address, (uint64_t)address + size);

    vm_map_unlock(map);

    return r;
}

int proc_mprotect(struct proc *p, void *address, void *end, int new_prot) {
    int r = 0;

    uint64_t addr = (uint64_t)address;
    uint64_t addrend = (uint64_t)end;

    struct vmspace *vm = p->p_vmspace;
    struct vm_map *map = &vm->vm_map;

    // update the max prot then set new prot
    r = vm_map_protect(map, addr, addrend, new_prot, 1);
    if (r) {
        return r;
    }

    r = vm_map_protect(map, addr, addrend, new_prot, 0);
    
    return r;
}

/*
  libkernel: _scePthreadAttrInit
  0000000000013656 90909090909090909090 nop:10
 >0000000000013660 55                   push rbp
  0000000000013661 4889E5               mov rbp, rsp
  0000000000013664 E89705FFFF           call 0x0000000000003C00
  0000000000013669 8D8800000280         lea ecx, [rax-0x7FFE0000]
  000000000001366F 85C0                 test eax, eax
  0000000000013671 0F45C1               cmovne eax, ecx
  0000000000013674 5D                   pop rbp
  0000000000013675 C3                   ret      

  Reference:
    AOB: 85 C0 BB 02 00 18-05
    0000000000012906 48893DCBEB0400 mov [0x614D8], rdi
    000000000001290D 488D3DD4EB0400 lea rdi, [0x614E8]
    0000000000012914 488915C5EB0400 mov [0x614E0], rdx
    000000000001291B E800810000     call 0x000000000001AA20
    0000000000012920 488D7DC8       lea rdi, [rbp-0x38]
    
   >0000000000012924 E8370D0000     call 0x0000000000013660
   
    0000000000012929 85C0           test eax, eax
    000000000001292B BB02001881     mov ebx, 0x81180002
    0000000000012930 759B           jne 0x00000000000128CD
    0000000000012932 BF0B000000     mov edi, 0xB
    0000000000012937 31F6           xor esi, esi
*/

/*
  libkernel: _scePthreadAttrSetstacksize
  DIRECTLY BELOW: _scePthreadAttrInit
   
  0000000000013676 90909090909090909090 nop:10
 >0000000000013680 55                   push rbp
  0000000000013681 4889E5               mov rbp, rsp
  0000000000013684 E88707FFFF           call 0x0000000000003E10
  0000000000013689 8D8800000280         lea ecx, [rax-0x7FFE0000]
  000000000001368F 85C0                 test eax, eax
  0000000000013691 0F45C1               cmovne eax, ecx
  0000000000013694 5D                   pop rbp
  0000000000013695 C3                   ret
  
  Reference (from libkernel_web)
    AOB: 48 8D 7D C0 E8 * * * * 81-05
    00000000000013F1 4C89FF         mov rdi, r15
    00000000000013F4 BE04000000     mov esi, 4
    00000000000013F9 E8B2FB0100     call 0x0000000000020FB0
    00000000000013FE 4C89FF         mov rdi, r15
    0000000000001401 4C89F6         mov rsi, r14
   >0000000000001404 E877910100     call 0x000000000001A580
    0000000000001409 488D7DC0       lea rdi, [rbp-0x40]
    000000000000140D E82E670200     call 0x0000000000027B40
    0000000000001412 817DC000000002 cmp dword ptr [rbp-0x40], 0x2000000
    0000000000001419 488D0D20F10200 lea rcx, [0x30540]
    0000000000001420 488D15A9F00200 lea rdx, [0x304D0]
*/

/*
  libkernel: _scePthreadCreate
  0000000000013A96 90909090909090909090 nop:10
 >0000000000013AA0 55                   push rbp
  0000000000013AA1 4889E5               mov rbp, rsp
  0000000000013AA4 E8B733FFFF           call 0x0000000000006E60
  0000000000013AA9 8D8800000280         lea ecx, [rax-0x7FFE0000]
  0000000000013AAF 85C0                 test eax, eax
  0000000000013AB1 0F45C1               cmovne eax, ecx
  0000000000013AB4 5D                   pop rbp
  0000000000013AB5 C3                   ret

  Reference:
    AOB: E8 * * * * 4C 89 FF 89 
   
    0000000000012992 4C89FE     mov rsi, r15
    0000000000012995 480F42D1   cmovb rdx, rcx
    0000000000012999 85C0       test eax, eax
    000000000001299B 480F45D1   cmovne rdx, rcx
    000000000001299F 31C9       xor ecx, ecx

   >00000000000129A1 E8FA100000 call 0x0000000000013AA0

    00000000000129A6 4C89FF     mov rdi, r15
    00000000000129A9 89C3       mov ebx, eax
    00000000000129AB E8F00B0000 call 0x00000000000135A0
    00000000000129B0 85DB       test ebx, ebx
    00000000000129B2 745A       je 0x0000000000012A0E
*/

/*
  libkernel: _thr_initial      
  Reference
    AOB: 48 8D 15 * * * * 48 83 3A 00
    
    0000000000002C7B 4885C0         test rax, rax
    0000000000002C7E 7405           je 0x0000000000002C85
    0000000000002C80 4889E9         mov rcx, rbp
    0000000000002C83 EB02           jmp 0x0000000000002C87
    0000000000002C85 31C9           xor ecx, ecx
   >0000000000002C87 488D15A2B70800 lea rdx, [0x8E430]
    0000000000002C8E 48833A00       cmp qword ptr [rdx], 0
    0000000000002C92 743C           je 0x0000000000002CD0
    0000000000002C94 488D70FF       lea rsi, [rax-1]
    0000000000002C98 4839CE         cmp rsi, rcx
    0000000000002C9B 730C           jae 0x0000000000002CA9
*/
int proc_create_thread(struct proc *p, uint64_t address) {
    void *rpcldraddr = NULL;
    void *stackaddr = NULL;
    struct proc_vm_map_entry *entries = NULL;
    uint64_t num_entries = 0;
    uint64_t n = 0;
    int r = 0;

    uint64_t ldrsize = sizeof(rpcldr);
    ldrsize += (PAGE_SIZE - (ldrsize % PAGE_SIZE));
    
    uint64_t stacksize = 0x80000;

    // allocate rpc ldr
    r = proc_allocate(p, &rpcldraddr, ldrsize);
    if (r) {
        goto error;
    }

    // allocate stack
    r = proc_allocate(p, &stackaddr, stacksize);
    if (r) {
        goto error;
    }

    // write loader
    r = proc_write_mem(p, rpcldraddr, sizeof(rpcldr), (void *)rpcldr, &n);
    if (r) {
        goto error;
    }

    // donor thread
    struct thread *thr = TAILQ_FIRST(&p->p_threads);

    // find libkernel base
    r = proc_get_vm_map(p, &entries, &num_entries);
    if (r) {
        goto error;
    }

    uint64_t _scePthreadAttrInit = 0, _scePthreadAttrSetstacksize = 0, _scePthreadCreate = 0, _thr_initial = 0;
    for (int i = 0; i < num_entries; i++) {
        if (entries[i].prot != (PROT_READ | PROT_EXEC)) {
            continue;
        }

        if (!memcmp(entries[i].name, "libkernel.sprx", 14)) {
            switch(cached_firmware) {
                case 505:
                    _scePthreadAttrInit = entries[i].start + 0x12660;
                    _scePthreadAttrSetstacksize = entries[i].start + 0x12680;
                    _scePthreadCreate = entries[i].start + 0x12AA0;
                    _thr_initial = entries[i].start + 0x84C20;
                    break;
                case 672:
                    _scePthreadAttrInit = entries[i].start + 0x13A40;
                    _scePthreadAttrSetstacksize = entries[i].start + 0x13A60;
                    _scePthreadCreate = entries[i].start + 0x13E80;
                    _thr_initial = entries[i].start + 0x435420;
                    break;
                case 702:
                    _scePthreadAttrInit = entries[i].start + 0x136E0;
                    _scePthreadAttrSetstacksize = entries[i].start + 0x13700;
                    _scePthreadCreate = entries[i].start + 0x13B20;
                    _thr_initial = entries[i].start + 0x8D420;
                    break;
                case 900:
                    _scePthreadAttrInit = entries[i].start + 0x13660;
                    _scePthreadAttrSetstacksize = entries[i].start + 0x13680;
                    _scePthreadCreate = entries[i].start + 0x13AA0;
                    _thr_initial = entries[i].start + 0x8E430;
                    break;
                case 1100:
                case 1202:
                case 1250:
                case 1300:
                    _scePthreadAttrInit = entries[i].start + 0x134A0;
                    _scePthreadAttrSetstacksize = entries[i].start + 0x134C0;
                    _scePthreadCreate = entries[i].start + 0x138E0;
                    _thr_initial = entries[i].start + 0x8E430;
                    break;
            }
            break;
        }
        if (!memcmp(entries[i].name, "libkernel_web.sprx", 18)) {
            switch(cached_firmware) {
                case 505:
                    _scePthreadAttrInit = entries[i].start + 0x1E730;
                    _scePthreadAttrSetstacksize = entries[i].start + 0xFA80;
                    _scePthreadCreate = entries[i].start + 0x98C0;
                    _thr_initial = entries[i].start + 0x84C20;
                    break;
                case 672:
                    _scePthreadAttrInit = entries[i].start + 0x1FD20;
                    _scePthreadAttrSetstacksize = entries[i].start + 0x10540;
                    _scePthreadCreate = entries[i].start + 0xA0F0;
                    _thr_initial = entries[i].start + 0x435420;
                    break;
                case 702:
                    _scePthreadAttrInit = entries[i].start + 0x1F9B0;
                    _scePthreadAttrSetstacksize = entries[i].start + 0x103C0;
                    _scePthreadCreate = entries[i].start + 0x9FF0;
                    _thr_initial = entries[i].start + 0x8D420;
                    break;
                case 900:
                    _scePthreadAttrInit = entries[i].start + 0x87F0;
                    _scePthreadAttrSetstacksize = entries[i].start + 0x1A580;
                    _scePthreadCreate = entries[i].start + 0x204C0;
                    _thr_initial = entries[i].start + 0x8E430;
                    break;
                case 1100:
                    _scePthreadAttrInit = entries[i].start + 0x15990;
                    _scePthreadAttrSetstacksize = entries[i].start + 0xE800;
                    _scePthreadCreate = entries[i].start + 0x20D90;
                    _thr_initial = entries[i].start + 0x8E430;
                    break;
                case 1202:
                    _scePthreadAttrInit = entries[i].start + 0x7A00;
                    _scePthreadAttrSetstacksize = entries[i].start + 0xEDA0;
                    _scePthreadCreate = entries[i].start + 0x9700;
                    _thr_initial = entries[i].start + 0x8E430;
                    break;
                case 1250:
                    _scePthreadAttrInit = entries[i].start + 0x69D0;
                    _scePthreadAttrSetstacksize = entries[i].start + 0x6E20;
                    _scePthreadCreate = entries[i].start + 0x9710;
                    _thr_initial = entries[i].start + 0x8E430;
                    break;
                case 1300:
                    _scePthreadAttrInit = entries[i].start + 0xFEC0;
                    _scePthreadAttrSetstacksize = entries[i].start + 0x15F40;
                    _scePthreadCreate = entries[i].start + 0x29F30;
                    _thr_initial = entries[i].start + 0x8E430;
                    break;
            }
            break;
        }
        if (!memcmp(entries[i].name, "libkernel_sys.sprx", 18)) {
            switch(cached_firmware) {
                case 505:
                    _scePthreadAttrInit = entries[i].start + 0x13190;
                    _scePthreadAttrSetstacksize = entries[i].start + 0x131B0;
                    _scePthreadCreate = entries[i].start + 0x135D0;
                    _thr_initial = entries[i].start + 0x89030;
                    break;
                case 672:
                    _scePthreadAttrInit = entries[i].start + 0x14570;
                    _scePthreadAttrSetstacksize = entries[i].start + 0x14590;
                    _scePthreadCreate = entries[i].start + 0x149B0;
                    _thr_initial = entries[i].start + 0x435830;
                    break;
                case 702:
                    _scePthreadAttrInit = entries[i].start + 0x14210;
                    _scePthreadAttrSetstacksize = entries[i].start + 0x14230;
                    _scePthreadCreate = entries[i].start + 0x14650;
                    _thr_initial = entries[i].start + 0x8D830;
                    break;
                case 900:
                    _scePthreadAttrInit = entries[i].start + 0x14190;
                    _scePthreadAttrSetstacksize = entries[i].start + 0x141B0;
                    _scePthreadCreate = entries[i].start + 0x145D0;
                    _thr_initial = entries[i].start + 0x8E830;
                    break;
                case 1100:
                case 1202:
                case 1250:
                case 1300:
                    _scePthreadAttrInit = entries[i].start + 0x14010;
                    _scePthreadAttrSetstacksize = entries[i].start + 0x14030; 
                    _scePthreadCreate = entries[i].start + 0x14450; 
                    _thr_initial = entries[i].start + 0x8E830;
                    break;
            }
            break;
        }
    }

    if (!_scePthreadAttrInit) {
        goto error;
    }

    // write variables
    r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, stubentry), sizeof(address), (void *)&address, &n);
    if (r) {
        goto error;
    }

    r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, scePthreadAttrInit), sizeof(_scePthreadAttrInit), (void *)&_scePthreadAttrInit, &n);
    if (r) {
        goto error;
    }

    r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, scePthreadAttrSetstacksize), sizeof(_scePthreadAttrSetstacksize), (void *)&_scePthreadAttrSetstacksize, &n);
    if (r) {
        goto error;
    }

    r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, scePthreadCreate), sizeof(_scePthreadCreate), (void *)&_scePthreadCreate, &n);
    if (r) {
        goto error;
    }

    r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, thr_initial), sizeof(_thr_initial), (void *)&_thr_initial, &n);
    if (r) {
        goto error;
    }

    // execute loader
    // note: do not enter in the pid information as it expects it to be stored in userland
    uint64_t ldrentryaddr = (uint64_t)rpcldraddr + *(uint64_t *)(rpcldr + 4);
    r = create_thread(thr, NULL, (void *)ldrentryaddr, NULL, stackaddr, stacksize, NULL, NULL, NULL, 0, NULL);
    if (r) {
        goto error;
    }

    // wait until loader is done
    uint8_t ldrdone = 0;
    while (!ldrdone) {
        r = proc_read_mem(p, (void *)(rpcldraddr + offsetof(struct rpcldr_header, ldrdone)), sizeof(ldrdone), &ldrdone, &n);
        if (r) {
            goto error;
        }
    }

error:
    if (entries) {
        free(entries, M_TEMP);
    }

    if (rpcldraddr) {
        proc_deallocate(p, rpcldraddr, ldrsize);
    }

    if (stackaddr) {
        proc_deallocate(p, stackaddr, stacksize);
    }

    return r;
}

int proc_map_elf(struct proc *p, void *elf, void *exec) {
    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

    struct Elf64_Phdr *phdr = elf_pheader(ehdr);
    if (phdr) {
        // use segments
        for (int i = 0; i < ehdr->e_phnum; i++) {
            struct Elf64_Phdr *phdr = elf_segment(ehdr, i);

            if (phdr->p_filesz) {
                proc_write_mem(p, (void *)((uint8_t *)exec + phdr->p_paddr), phdr->p_filesz, (void *)((uint8_t *)elf + phdr->p_offset), NULL);
            }
        }
    }
    else {
        // use sections
        for (int i = 0; i < ehdr->e_shnum; i++) {
            struct Elf64_Shdr *shdr = elf_section(ehdr, i);

            if (!(shdr->sh_flags & SHF_ALLOC)) {
                continue;
            }

            if (shdr->sh_size) {
                proc_write_mem(p, (void *)((uint8_t *)exec + shdr->sh_addr), shdr->sh_size, (void *)((uint8_t *)elf + shdr->sh_offset), NULL);
            }
        }
    }

    return 0;
}

int proc_relocate_elf(struct proc *p, void *elf, void *exec) {
    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        struct Elf64_Shdr *shdr = elf_section(ehdr, i);

        // check table
        if (shdr->sh_type == SHT_REL) {
            // process each entry in the table
            for (int j = 0; j < shdr->sh_size / shdr->sh_entsize; j++) {
                struct Elf64_Rela *reltab = &((struct Elf64_Rela *)((uint64_t)ehdr + shdr->sh_offset))[j];
                uint8_t **ref = (uint8_t **)((uint8_t *)exec + reltab->r_offset);
                uint8_t *value = NULL;

                switch (ELF64_R_TYPE(reltab->r_info)) {
                case R_X86_64_RELATIVE:
                    // *ref = (uint8_t *)exec + reltab->r_addend;
                    value = (uint8_t *)exec + reltab->r_addend;
                    proc_write_mem(p, ref, sizeof(value), (void *)&value, NULL);
                    break;
                case R_X86_64_64:
                case R_X86_64_JUMP_SLOT:
                case R_X86_64_GLOB_DAT:
                    // not supported
                    break;
                }
            }
        }
    }

    return 0;
}

int proc_load_elf(struct proc *p, void *elf, uint64_t *elfbase, uint64_t *entry) {
    void *elfaddr = NULL;
    uint64_t msize = 0;
    int r = 0;

    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

    r = elf_mapped_size(elf, &msize);
    if (r) {
        goto error;
    }

    // resize to pages
    msize += (PAGE_SIZE - (msize % PAGE_SIZE));

    // allocate
    r = proc_allocate(p, &elfaddr, msize);
    if (r) {
        goto error;
    }

    // map
    r = proc_map_elf(p, elf, elfaddr);
    if (r) {
        goto error;
    }

    // relocate
    r = proc_relocate_elf(p, elf, elfaddr);
    if (r) {
        goto error;
    }

    if (elfbase) {
        *elfbase = (uint64_t)elfaddr;
    }

    if (entry) {
        *entry = (uint64_t)elfaddr + ehdr->e_entry;
    }

error:
    return r;
}
