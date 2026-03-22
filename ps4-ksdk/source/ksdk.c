#include "ksdk.h"

uint64_t cached_kernel_base;

int(*printf)(const char *fmt, ... );
void *(*malloc)(uint64_t size, void *type, int flags);
void(*free)(void *addr, void *type);
void *(*memcpy)(void *dest, const void *src, uint64_t num);
void *(*memset)(void *ptr, int value, uint64_t num);
int(*memcmp)(const void *ptr1, const void *ptr2, uint64_t num);
void *(*kmem_alloc)(struct vm_map *map, uint64_t size);
uint64_t(*strlen)(const char *str);
char *(*strcpy)(char *dst, const char *src);
int(*create_thread)(struct thread *td, uint64_t ctx, void (*start_func)(void *), void *arg, char *stack_base, uint64_t stack_size, char *tls_base, long *child_tid, long *parent_tid, uint64_t flags, uint64_t rtp);
int(*kern_reboot)(int magic);
void(*vm_map_lock_read)(struct vm_map *map);
int(*vm_map_lookup_entry)(struct vm_map *map, uint64_t address, struct vm_map_entry **entries);
void(*vm_map_unlock_read)(struct vm_map *map);
int(*vm_map_delete)(struct vm_map *map, uint64_t start, uint64_t end);
int(*vm_map_protect)(struct vm_map *map, uint64_t start, uint64_t end, int new_prot, uint64_t set_max);
int(*vm_map_findspace)(struct vm_map *map, uint64_t start, uint64_t length, uint64_t *addr);
int(*vm_map_insert)(struct vm_map *map, uint64_t object, uint64_t offset, uint64_t start, uint64_t end, int prot, int max, int cow);
void(*vm_map_lock)(struct vm_map *map);
void(*vm_map_unlock)(struct vm_map *map);
int(*proc_rwmem)(struct proc *p, struct uio *uio);
uint64_t(*pmap_kextract)(uint64_t va);
void *(*pmap_mapdev)(uint64_t pa, uint64_t size);
void(*pmap_unmapdev)(uint64_t va, uint64_t size);

uint8_t *disable_console_output;
void *M_TEMP;
void **kernel_map;
void **prison0;
void **rootvnode;
void **allproc;
struct sysent *sysents;

uint64_t get_kernel_base() {
    uint32_t edx, eax;
    __asm__ ("rdmsr" : "=d"(edx), "=a"(eax) : "c"(0xC0000082));
    return ((((uint64_t)edx) << 32) | (uint64_t)eax) - __Xfast_syscall;
}

void init_ksdk() {
    cached_kernel_base = get_kernel_base();
    unsigned short firmwareVersion = kget_firmware_from_base(cached_kernel_base);

    switch (firmwareVersion) {
        case 505:
        case 672:
        case 702:
        case 900:
        case 1100:
        case 1202:
// Missing Offset
//        case 1250:
//        case 1300:
            break;
        default:
            return;
    }
    
    /*
      printf
      AOB: 48 8B 03 48 89 45 F0 48 B8 08 00 00 00 30 00 00 00 48 89 55 E0 48 89 4D D8 48 89 45 D0 E8 * * * * 48 8B 0B-0x30

      00000000000B7A27 909090909090909090 nop:9
    ->00000000000B7A30 55                 push rbp
      00000000000B7A31 4889E5             mov rbp, rsp
      00000000000B7A34 53                 push rbx
      00000000000B7A35 4883EC58           sub rsp, 0x58
      00000000000B7A39 488D1DD0456902     lea rbx, [rip+0x26945D0]
      00000000000B7A40 488975A8           mov [rbp-0x58], rsi
      00000000000B7A44 488955B0           mov [rbp-0x50], rdx
      00000000000B7A48 48894DB8           mov [rbp-0x48], rcx
      00000000000B7A4C 4C8945C0           mov [rbp-0x40], r8
      00000000000B7A50 4C894DC8           mov [rbp-0x38], r9
    */
    uint32_t uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x436040;
            break;
        case 672:
            uiOffset = 0x123280;
            break;
        case 702:
            uiOffset = 0xBC730;
            break;
        case 900:
            uiOffset = 0xB7A30;
            break;
        case 1100:
            uiOffset = 0x2FCBD0;
            break;
        case 1202:
            uiOffset = 0x2E03E0;
            break;    
        case 1250:
            uiOffset = 0x2E0420;
            break;
        case 1300:
            uiOffset = 0x2E0440;
            break;
    }    
    printf = (void *)(cached_kernel_base + uiOffset);
    
    /*
      AOB:

    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x10E250;
            break;
        case 672:
            uiOffset = 0xD7A0;
            break;
        case 702:
            uiOffset = 0x301840;
            break;
        case 900:
            uiOffset = 0x301B20;
            break;
        case 1100:
            uiOffset = 0x1A4220;
            break;
        case 1202:
        case 1250:
        case 1300:
            uiOffset = 0x9520;
            break;
    }      
    malloc = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB:

    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x10E460;
            break;
        case 672:
            uiOffset = 0xD9A0;
            break;
        case 702:
            uiOffset = 0x301A40;
            break;
        case 900:
            uiOffset = 0x301CE0;
            break;
        case 1100:
            uiOffset = 0x1A43E0;
            break;
        case 1202:
        case 1250:
        case 1300:
            uiOffset = 0x96E0;
            break;
    }  
    free = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB: C0 C3 0F 1F 00 55+05

      00000000002714A4 F3A6   repe cmpsb
      00000000002714A6 0F95C0 setne al
      00000000002714A9 0FBEC0 movsx eax, al
      00000000002714AC C3     ret
      00000000002714AD 0F1F00 nop dword ptr [rax]
    ->00000000002714B0 55     push rbp
      00000000002714B1 4889E5 mov rbp, rsp
      00000000002714B4 4989FA mov r10, rdi
      00000000002714B7 4901D2 add r10, rdx
      00000000002714BA 4939E2 cmp r10, rsp
      00000000002714BD 7617   jbe 0x00000000002714D6
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x1EA530;
            break;
        case 672:
            uiOffset = 0x3C15B0;
            break;
        case 702:
            uiOffset = 0x2F040;
            break;
        case 900:
            uiOffset = 0x2714B0;
            break;
        case 1100:
            uiOffset = 0x2DDDF0;
            break;
        case 1202:
            uiOffset = 0x2BD480;
            break;    
        case 1250:
            uiOffset = 0x2BD4C0;
            break;
        case 1300:
            uiOffset = 0x2BD4E0;
            break;
    }  
    memcpy = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB: 90 90 90 90 90 90 90 55 48 89 E5 53 50 48 89 FB 85 F6 74 21+07

    ->00000000001496C0 55     push rbp
      00000000001496C1 4889E5 mov rbp, rsp
      00000000001496C4 53     push rbx
      00000000001496C5 50     push rax
      00000000001496C6 4889FB mov rbx, rdi
      00000000001496C9 85F6   test esi, esi
      00000000001496CB 7421   je 0x00000000001496EE
      00000000001496CD 4885D2 test rdx, rdx
      00000000001496D0 7427   je 0x00000000001496F9
      00000000001496D2 4889D8 mov rax, rbx
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x3205C0;
            break;
        case 672:
            uiOffset = 0x1687D0;
            break;
        case 702:
            uiOffset = 0x2DFC20;
            break;
        case 900:
            uiOffset = 0x1496C0;
            break;
        case 1100:
            uiOffset = 0x482D0;
            break;
        case 1202:
            uiOffset = 0x1FA140;
            break;    
        case 1250:
            uiOffset = 0x1FA180;
            break;
        case 1300:
            uiOffset = 0x1FA1A0;
            break;
    }  
    memset = (void *)(cached_kernel_base + uiOffset);
    
    /*
      AOB: 90 90 55 48 89 E5 48 85 D2 74* 31 C9 0F 1F 44 00 00 0F B6 04 0F+2

    ->0000000000271E20 55         push rbp
      0000000000271E21 4889E5     mov rbp, rsp
      0000000000271E24 4885D2     test rdx, rdx
      0000000000271E27 741D       je 0x0000000000271E46
      0000000000271E29 31C9       xor ecx, ecx
      0000000000271E2B 0F1F440000 nop dword ptr [rax+rax]
      0000000000271E30 0FB6040F   movzx eax, byte ptr [rdi+rcx]
      0000000000271E34 440FB6040E movzx r8d, byte ptr [rsi+rcx]
      0000000000271E39 4438C0     cmp al, r8b
      0000000000271E3C 750C       jne 0x0000000000271E4A
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x50AC0;
            break;
        case 672:
            uiOffset = 0x207E40;
            break;
        case 702:
            uiOffset = 0x207500;
            break;
        case 900:
            uiOffset = 0x271E20;
            break;
        case 1100:
            uiOffset = 0x948B0;
            break;
        case 1202:
            uiOffset = 0x3942A0;
            break;    
        case 1250:
            uiOffset = 0x3942E0;
            break;
        case 1300:
            uiOffset = 0x394300;
            break;
    }  
    memcmp = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB: 4C 8D 2D * * * * 48 81 FE FF 7F FF FF-0x11

    ->00000000001170F0 55             push rbp
      00000000001170F1 4889E5         mov rbp, rsp
      00000000001170F4 4157           push r15
      00000000001170F6 4156           push r14
      00000000001170F8 4155           push r13
      00000000001170FA 4154           push r12
      00000000001170FC 53             push rbx
      00000000001170FD 4883EC18       sub rsp, 0x18
      0000000000117101 4C8D2D78D36402 lea r13, [rip+0x264D378]
      0000000000117108 4881FEFF7FFFFF cmp rsi, 0xFFFFFFFFFFFF7FFF
      000000000011710F 498B4500       mov rax, [r13]
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0xFCC80;
            break;
        case 672:
            uiOffset = 0x250730;
            break;
        case 702:
            uiOffset = 0x1170F0;
            break;
        case 900:
            uiOffset = 0x37BE70;
            break;
        case 1100:
            uiOffset = 0x245E10;
            break;
        case 1202:
            uiOffset = 0x4659E0;
            break;    
        case 1250:
            uiOffset = 0x465A20;
            break;
        case 1300:
            uiOffset = 0x465A40;
            break;
    }  
    kmem_alloc = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB: 55 48 89 E5 48 8D 47 FF

    ->000000000036AB90 55               push rbp
      000000000036AB91 4889E5           mov rbp, rsp
      000000000036AB94 488D47FF         lea rax, [rdi-1]
      000000000036AB98 0F1F840000000000 nop dword ptr [rax+rax]
      000000000036ABA0 80780100         cmp byte ptr [rax+1], 0
      000000000036ABA4 488D4001         lea rax, [rax+1]
      000000000036ABA8 75F6             jne 0x000000000036ABA0
      000000000036ABAA 4829F8           sub rax, rdi
      000000000036ABAD 5D               pop rbp
      000000000036ABAE C3               ret
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x3B71A0;
            break;
        case 672:
            uiOffset = 0x2433E0;
            break;
        case 702:
            uiOffset = 0x93FF0;
            break;
        case 900:
            uiOffset = 0x30F450;
            break;
        case 1100:
            uiOffset = 0x21DC40;
            break;
        case 1202:
            uiOffset = 0x36AB30;
            break;    
        case 1250:
            uiOffset = 0x36AB70;
            break;
        case 1300:
            uiOffset = 0x36AB90;
            break;
    }  
    strlen = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB: 55 48 89 E5 8A 0E 48 89

    ->0000000000189F80 55                       push rbp
      0000000000189F81 4889E5                   mov rbp, rsp
      0000000000189F84 8A0E                     mov cl, [rsi]
      0000000000189F86 4889F8                   mov rax, rdi
      0000000000189F89 84C9                     test cl, cl
      0000000000189F8B 880F                     mov [rdi], cl
      0000000000189F8D 741F                     je 0x0000000000189FAE
      0000000000189F8F B901000000               mov ecx, 1
      0000000000189F94 6666662E0F1F840000000000 nop word ptr [rax+rax]
      0000000000189FA0 0FB6140E                 movzx edx, byte ptr [rsi+rcx]
      0000000000189FA4 881408                   mov [rax+rcx], dl
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x8F250;
            break;
        case 672:
            uiOffset = 0x2390C0;
            break;
        case 702:
            uiOffset = 0x2CC70;
            break;
        case 900:
            uiOffset = 0x189F80;
            break;
        case 1100:
            uiOffset = 0x1AA590;
            break;
        case 1202:
            uiOffset = 0x417680;
            break;    
        case 1250:
            uiOffset = 0x4176C0;
            break;
        case 1300:
            uiOffset = 0x4176E0;
            break;
    }  
    strcpy = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB: 55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 48 49 89 F5

      00000000001ED667 909090909090909090 nop:9
    ->00000000001ED670 55                 push rbp
      00000000001ED671 4889E5             mov rbp, rsp
      00000000001ED674 4157               push r15
      00000000001ED676 4156               push r14
      00000000001ED678 4155               push r13
      00000000001ED67A 4154               push r12
      00000000001ED67C 53                 push rbx
      00000000001ED67D 4883EC48           sub rsp, 0x48
      00000000001ED681 4989F5             mov r13, rsi
      00000000001ED684 488D3585E95502     lea rsi, [rip+0x255E985]
      00000000001ED68B 488B06             mov rax, [rsi]
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x1BE1F0;
            break;
        case 672:
            uiOffset = 0x4A6FB0;
            break;
        case 702:
            uiOffset = 0x842E0;
            break;
        case 900:
            uiOffset = 0x1ED670;
            break;
        case 1100:
            uiOffset = 0x295170;
            break;
        case 1202:    
        case 1250:
        case 1300:
            uiOffset = 0x4C6C0;
            break;
    }  
    create_thread = (void *)(cached_kernel_base + uiOffset);
    
    /*
      AOB: 55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 28 4C 8D 35 * * * * 41 89 FD
      
      000000000029A371 909090909090909090909090909090 nop:15
    ->000000000029A380 55                             push rbp
      000000000029A381 4889E5                         mov rbp, rsp
      000000000029A384 4157                           push r15
      000000000029A386 4156                           push r14
      000000000029A388 4155                           push r13
      000000000029A38A 4154                           push r12
      000000000029A38C 53                             push rbx
      000000000029A38D 4883EC28                       sub rsp, 0x28
      000000000029A391 4C8D3543CC5300                 lea r14, [rip+0x53CC43]
      000000000029A398 4189FD                         mov r13d, edi
      000000000029A39B 65488B1C2500000000             mov rbx, gs:[0]
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x10D390;
            break;
        case 672:
            uiOffset = 0x206D50;
            break;
        case 702:
            uiOffset = 0x2CD780;
            break;
        case 900:
            uiOffset = 0x29A380;
            break;
        case 1100:
            uiOffset = 0x198060;
            break;
        case 1202:
            uiOffset = 0x3A1D70;
            break;    
        case 1250:
            uiOffset = 0x3A1DB0;
            break;
        case 1300:
            uiOffset = 0x3A1DD0;
            break;
    }  
    kern_reboot = (void *)(cached_kernel_base + uiOffset);
    
    /*
      AOB: 55 48 89 E5 80 BF * 01 00 00 00 89

      00000000002F710A 909090909090   nop:6
    ->00000000002F7110 55             push rbp
      00000000002F7111 4889E5         mov rbp, rsp
      00000000002F7114 80BF1A01000000 cmp byte ptr [rdi+0x11A], 0
      00000000002F711B 89D1           mov ecx, edx
      00000000002F711D 4889F2         mov rdx, rsi
      00000000002F7120 740F           je 0x00000000002F7131
      00000000002F7122 4881C7E0000000 add rdi, 0xE0
      00000000002F7129 31F6           xor esi, esi
      00000000002F712B 5D             pop rbp
      00000000002F712C E9EF110800     jmp 0x0000000000378320
      00000000002F7131 80BF1801000000 cmp byte ptr [rdi+0x118], 0
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x19F140;
            break;
        case 672:
            uiOffset = 0x44CD40;
            break;
        case 702:
            uiOffset = 0x25FB90;
            break;
        case 900:
            uiOffset = 0x7BB80;
            break;
        case 1100:
            uiOffset = 0x3578B0;
            break;
        case 1202:
            uiOffset = 0x2F70B0;
            break;    
        case 1250:
            uiOffset = 0x2F70F0;
            break;
        case 1300:
            uiOffset = 0x2F7110;
            break;
    }      
    vm_map_lock_read = (void *)(cached_kernel_base + uiOffset);
    
    /*
      AOB: 55 48 89 E5 41 57 41 56 41 55 41 54 53 50 48 8B 9F * 01 00 00 49 89 D6

      000000000007C1B1 909090909090909090909090909090 nop:15
    ->000000000007C1C0 55                             push rbp
      000000000007C1C1 4889E5                         mov rbp, rsp
      000000000007C1C4 4157                           push r15
      000000000007C1C6 4156                           push r14
      000000000007C1C8 4155                           push r13
      000000000007C1CA 4154                           push r12
      000000000007C1CC 53                             push rbx
      000000000007C1CD 50                             push rax
      000000000007C1CE 488B9F20010000                 mov rbx, [rdi+0x120]
      000000000007C1D5 4989D6                         mov r14, rdx
      000000000007C1D8 4989FC                         mov r12, rdi
      000000000007C1DB 4885DB                         test rbx, rbx
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x19F760;
            break;
        case 672:
            uiOffset = 0x44D330;
            break;
        case 702:
            uiOffset = 0x260190;
            break;
        case 900:
            uiOffset = 0x7C1C0;
            break;
        case 1100:
            uiOffset = 0x357EF0;
            break;
        case 1202:
            uiOffset = 0x2F76F0;
            break;    
        case 1250:
            uiOffset = 0x2F7709;
            break;
        case 1300:
            uiOffset = 0x2F7750;
            break;
    }      
    vm_map_lookup_entry = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB: 00 31 F6 5D E9 * * * * 90 90 90 90 90 90 55+0F

      000000000007BBCA 909090909090   nop:6
    ->000000000007BBD0 55             push rbp
      000000000007BBD1 4889E5         mov rbp, rsp
      000000000007BBD4 4156           push r14
      000000000007BBD6 53             push rbx
      000000000007BBD7 80BF1A01000000 cmp byte ptr [rdi+0x11A], 0
      000000000007BBDE 89D1           mov ecx, edx
      000000000007BBE0 4889F2         mov rdx, rsi
      000000000007BBE3 4889FB         mov rbx, rdi
      000000000007BBE6 7415           je 0x000000000007BBFD
      000000000007BBE8 4881C3E0000000 add rbx, 0xE0
      000000000007BBEF 31F6           xor esi, esi
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x19F190;
            break;
        case 672:
            uiOffset = 0x44CD90;
            break;
        case 702:
            uiOffset = 0x25FBE0;
            break;
        case 900:
            uiOffset = 0x7BBD0;
            break;
        case 1100:
            uiOffset = 0x357900;
            break;
        case 1202:
            uiOffset = 0x2F7100;
            break;    
        case 1250:
            uiOffset = 0x2F7140;
            break;
        case 1300:
            uiOffset = 0x2F7160;
            break;
    }  
    vm_map_unlock_read = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB: 55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 38 48 8D 05 * * * 02 49 89 D6 49 89 F7

      000000000007E674 909090909090909090909090 nop:12
    ->000000000007E680 55                       push rbp
      000000000007E681 4889E5                   mov rbp, rsp
      000000000007E684 4157                     push r15
      000000000007E686 4156                     push r14
      000000000007E688 4155                     push r13
      000000000007E68A 4154                     push r12
      000000000007E68C 53                       push rbx
      000000000007E68D 4883EC38                 sub rsp, 0x38
      000000000007E691 488D0578D96C02           lea rax, [rip+0x26CD978]
      000000000007E698 4989D6                   mov r14, rdx
      000000000007E69B 4989F7                   mov r15, rsi
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x1A19D0;
            break;
        case 672:
            uiOffset = 0x44F8A0;
            break;
        case 702:
            uiOffset = 0x262700;
            break;
        case 900:
            uiOffset = 0x7E680;
            break;
        case 1100:
            uiOffset = 0x35A3B0;
            break;
        case 1202:
            uiOffset = 0x2F9BB0;
            break;    
        case 1250:
            uiOffset = 0x2F9BF0;
            break;
        case 1300:
            uiOffset = 0x2F9C10;
            break;
    }  
    vm_map_delete = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB (9.00+): AB 90 90 90 90 55+05

      00000000002FBF4C 90909090       nop:4
    ->00000000002FBF50 55             push rbp
      00000000002FBF51 4889E5         mov rbp, rsp
      00000000002FBF54 4157           push r15
      00000000002FBF56 4156           push r14
      00000000002FBF58 4155           push r13
      00000000002FBF5A 4154           push r12
      00000000002FBF5C 53             push rbx
      00000000002FBF5D 4881EC98000000 sub rsp, 0x98
      00000000002FBF64 488D05350F4602 lea rax, [rip+0x2460F35]
      00000000002FBF6B 448945A4       mov [rbp-0x5C], r8d
      00000000002FBF6F 894DB4         mov [rbp-0x4C], ecx
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x1A3A50;
            break;
        case 672:
            uiOffset = 0x451BF0;
            break;
        case 702:
            uiOffset = 0x264A50;
            break;
        case 900:
            uiOffset = 0x809C0;
            break;
        case 1100:
            uiOffset = 0x35C710;
            break;
        case 1202:
            uiOffset = 0x2FBF10;
            break;    
        case 1250:
            uiOffset = 0x2FBF50;
            break;
        case 1300:
            uiOffset = 0x2FBF70;
            break;
    }  
    vm_map_protect = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB (9.00+): 8C FE FF FF 90 90 90 55+07

      000000000007EC3D 909090       nop:3
    ->000000000007EC40 55           push rbp
      000000000007EC41 4889E5       mov rbp, rsp
      000000000007EC44 4157         push r15
      000000000007EC46 4156         push r14
      000000000007EC48 4155         push r13
      000000000007EC4A 4154         push r12
      000000000007EC4C 53           push rbx
      000000000007EC4D 50           push rax
      000000000007EC4E 488B4720     mov rax, [rdi+0x20]
      000000000007EC52 4989F6       mov r14, rsi
      000000000007EC55 41BF01000000 mov r15d, 1
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x1A1F60;
            break;
        case 672:
            uiOffset = 0x44FE60;
            break;
        case 702:
            uiOffset = 0x262CC0;
            break;
        case 900:
            uiOffset = 0x7EC40;
            break;
        case 1100:
            uiOffset = 0x35A970;
            break;
        case 1202:
            uiOffset = 0x2FA170;
            break;    
        case 1250:
            uiOffset = 0x2FA1B0;
            break;
        case 1300:
            uiOffset = 0x2FA1D0;
            break;
    }  
    vm_map_findspace = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB (9.00+): 55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 78 4C 8D 3D * * * * 48 89 CB

      000000000007CD77 909090909090909090 nop:9
    ->000000000007CD80 55                 push rbp
      000000000007CD81 4889E5             mov rbp, rsp
      000000000007CD84 4157               push r15
      000000000007CD86 4156               push r14
      000000000007CD88 4155               push r13
      000000000007CD8A 4154               push r12
      000000000007CD8C 53                 push rbx
      000000000007CD8D 4883EC78           sub rsp, 0x78
      000000000007CD91 4C8D3D78F26C02     lea r15, [rip+0x26CF278]
      000000000007CD98 4889CB             mov rbx, rcx
      000000000007CD9B 8B4D18             mov ecx, [rbp+0x18]
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x1A0280;
            break;
        case 672:
            uiOffset = 0x44DEF0;
            break;
        case 702:
            uiOffset = 0x260D60;
            break;
        case 900:
            uiOffset = 0x7CD80;
            break;
        case 1100:
            uiOffset = 0x358AB0;
            break;
        case 1202:
            uiOffset = 0x2F82B0;
            break;    
        case 1250:
            uiOffset = 0x2F82F0;
            break;
        case 1300:
            uiOffset = 0x2F8310;
            break;
    }  
    vm_map_insert = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB (9.00+): 55 48 89 E5 53 50 80 BF 1A

      000000000007BA24 909090909090909090909090 nop:12
    ->000000000007BA30 55                       push rbp
      000000000007BA31 4889E5                   mov rbp, rsp
      000000000007BA34 53                       push rbx
      000000000007BA35 50                       push rax
      000000000007BA36 80BF1A01000000           cmp byte ptr [rdi+0x11A], 0
      000000000007BA3D 89D1                     mov ecx, edx
      000000000007BA3F 4889F2                   mov rdx, rsi
      000000000007BA42 4889FB                   mov rbx, rdi
      000000000007BA45 7410                     je 0x000000000007BA57
      000000000007BA47 488DBBE0000000           lea rdi, [rbx+0xE0]
      000000000007BA4E 31F6                     xor esi, esi
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x19EFF0;
            break;
        case 672:
            uiOffset = 0x44CBF0;
            break;
        case 702:
            uiOffset = 0x25FA50;
            break;
        case 900:
            uiOffset = 0x7BA30;
            break;
        case 1100:
            uiOffset = 0x357760;
            break;
        case 1202:
            uiOffset = 0x2F6F60;
            break;    
        case 1250:
            uiOffset = 0x2F6FA0;
            break;
        case 1300:
            uiOffset = 0x2F6FC0;
            break;
    }  
    vm_map_lock = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB (9.00+): 90 90 90 90 90 90 90 55 48 89 E5 41 56 53 80 BF 1A+07

      000000000007BA94 909090909090909090909090 nop:12
    ->000000000007BAA0 55                       push rbp
      000000000007BAA1 4889E5                   mov rbp, rsp
      000000000007BAA4 4156                     push r14
      000000000007BAA6 53                       push rbx
      000000000007BAA7 80BF1A01000000           cmp byte ptr [rdi+0x11A], 0
      000000000007BAAE 89D1                     mov ecx, edx
      000000000007BAB0 4889F2                   mov rdx, rsi
      000000000007BAB3 4889FB                   mov rbx, rdi
      000000000007BAB6 7415                     je 0x000000000007BACD
      000000000007BAB8 4881C3E0000000           add rbx, 0xE0
      000000000007BABF 31F6                     xor esi, esi
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x19F060;
            break;
        case 672:
            uiOffset = 0x44CC60;
            break;
        case 702:
            uiOffset = 0x25FAB0;
            break;
        case 900:
            uiOffset = 0x7BAA0;
            break;
        case 1100:
            uiOffset = 0x3577D0;
            break;
        case 1202:
            uiOffset = 0x2F6FD0;
            break;    
        case 1250:
            uiOffset = 0x2F7010;
            break;
        case 1300:
            uiOffset = 0x2F7030;
            break;
    }  
    vm_map_unlock = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB: 49 89 F6 48 89 FB B9-0x18

      000000000041EAFE 9090           nop:2
    ->000000000041EB00 55             push rbp
      000000000041EB01 4889E5         mov rbp, rsp
      000000000041EB04 4157           push r15
      000000000041EB06 4156           push r14
      000000000041EB08 4155           push r13
      000000000041EB0A 4154           push r12
      000000000041EB0C 53             push rbx
      000000000041EB0D 4883EC48       sub rsp, 0x48
      000000000041EB11 488D05F8D43202 lea rax, [rip+0x232D4F8]
      000000000041EB18 4989F6         mov r14, rsi
      000000000041EB1B 4889FB         mov rbx, rdi
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x30D150;
            break;
        case 672:
            uiOffset = 0x10EE10;
            break;
        case 702:
            uiOffset = 0x43E80;
            break;
        case 900:
            uiOffset = 0x41EB00;
            break;
        case 1100:
            uiOffset = 0x3838A0;
            break;
        case 1202:
            uiOffset = 0x365FA0;
            break;    
        case 1250:
            uiOffset = 0x365FE0;
            break;
        case 1300:
            uiOffset = 0x366000;
            break;
    }  
    proc_rwmem = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB (9.00+): 49 B8 00 00 00 00 00 80 FF FF 48 89-0x13

    ->000000000012D3B0 55                   push rbp
      000000000012D3B1 4889E5               mov rbp, rsp
      000000000012D3B4 8B15EA30A601         mov edx, [rip+0x1A630EA]
      000000000012D3BA 8B0DE830A601         mov ecx, [rip+0x1A630E8]
      000000000012D3C0 4889F8               mov rax, rdi
      000000000012D3C3 49B8000000000080FFFF mov r8, 0xFFFF800000000000
      000000000012D3CD 4889D7               mov rdi, rdx
      000000000012D3D0 48C1E11E             shl rcx, 0x1E
      000000000012D3D4 48C1E727             shl rdi, 0x27
      000000000012D3D8 4809F9               or rcx, rdi
      000000000012D3DB 4C09C1               or rcx, r8
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x2E08F0;
            break;
        case 672:
            uiOffset = 0x4E790;
            break;
        case 702:
            uiOffset = 0x3DF0A0;
            break;
        case 900:
            uiOffset = 0x12D3B0;
            break;
        case 1100:
            uiOffset = 0x1145F0;
            break;
        case 1202:   
        case 1250:
        case 1300:
            uiOffset = 0x57730;
            break;
    }  
    pmap_kextract = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB: 55 48 89 E5 31 D2 5D E9 F4 FC FF FF

      000000000013779A 909090909090 nop:6
    ->00000000001377A0 55           push rbp
      00000000001377A1 4889E5       mov rbp, rsp
      00000000001377A4 31D2         xor edx, edx
      00000000001377A6 5D           pop rbp
      00000000001377A7 E9F4FCFFFF   jmp 0x00000000001374A0
      00000000001377AC 90909090     nop:4
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x2E9D90;
            break;
        case 672:
            uiOffset = 0x58FC0;
            break;
        case 702:
            uiOffset = 0x3E9880;
            break;
        case 900:
            uiOffset = 0x1377A0;
            break;
        case 1100:
            uiOffset = 0x11E9A0;
            break;
        case 1202:  
        case 1250:
        case 1300:
            uiOffset = 0x61AE0;
            break;
    }  
    pmap_mapdev = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB: E1 FC FF FF 90 55+05

      00000000001377BF 90           nop
    ->00000000001377C0 55           push rbp
      00000000001377C1 4889E5       mov rbp, rsp
      00000000001377C4 4157         push r15
      00000000001377C6 4156         push r14
      00000000001377C8 4155         push r13
      00000000001377CA 4154         push r12
      00000000001377CC 53           push rbx
      00000000001377CD 50           push rax
      00000000001377CE 8B0DD08CA501 mov ecx, [rip+0x1A58CD0]
      00000000001377D4 4989FE       mov r14, rdi
      00000000001377D7 8B3DCB8CA501 mov edi, [rip+0x1A58CCB]
    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x2E9DB0;
            break;
        case 672:
            uiOffset = 0x58FE0;
            break;
        case 702:
            uiOffset = 0x3E98A0;
            break;
        case 900:
            uiOffset = 0x1377C0;
            break;
        case 1100:
            uiOffset = 0x11E9C0;
            break;
        case 1202:  
        case 1250:
        case 1300:
            uiOffset = 0x61B00;
            break;
    }  
    pmap_unmapdev = (void *)(cached_kernel_base + uiOffset);

    /*
      Module: ?
      AOB:

    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x19ECEB0;
            break;
        case 672:
            uiOffset = 0x1A6EB18;
            break;
        case 702:
            uiOffset = 0x1A6EAA0;
            break;
        case 900:
            uiOffset = 0x152BF60;
            break;
        case 1100:
            uiOffset = 0x152CFF8;
            break;
        case 1202:
            uiOffset = 0x1A47F40;
            break;    
        case 1250: // Missing Offset
            uiOffset = 0x0;
            break;
        case 1300: // Missing Offset
            uiOffset = 0x0;
            break;
    }  
    disable_console_output = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB:

    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x14B4110;
            break;
        case 672:
            uiOffset = 0x1540EB0;
            break;
        case 702:
            uiOffset = 0x1A7AE50;
            break;
        case 900:
            uiOffset = 0x15621E0;
            break;
        case 1100:
            uiOffset = 0x15415B0;
            break;
        case 1202:
            uiOffset = 0x1520D00;
            break;    
        case 1250: // Missing Offset
            uiOffset = 0x0;
            break;
        case 1300: // Missing Offset
            uiOffset = 0x0;
            break;
    }  
    M_TEMP = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB:

    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x1AC60E0;
            break;
        case 672:
            uiOffset = 0x220DFC0;
            break;
        case 702:
            uiOffset = 0x21C8EE0;
            break;
        case 900:
            uiOffset = 0x2268D48;
            break;
        case 1100:
            uiOffset = 0x21FF130;
            break;
        case 1202:
            uiOffset = 0x22D1D50;
            break;    
        case 1250:
            uiOffset = 0x0; // Missing Offset
            break;
        case 1300:
            uiOffset = 0x0; // Missing Offset
            break;
    }  
    kernel_map = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB:

    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x10986A0;
            break;
        case 672:
            uiOffset = 0x113E518;
            break;
        case 702:
            uiOffset = 0x113E398;
            break;
        case 900:
            uiOffset = 0x111F870;
            break;
        case 1100:
            uiOffset = 0x111F830;
            break;
        case 1202:
            uiOffset = 0x111FA18;
            break;    
        case 1250:
            uiOffset = 0x0; // Missing Offset
            break;
        case 1300:
            uiOffset = 0x0; // Missing Offset
            break;
    }  
    prison0 = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB:

    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x22C1A70;
            break;
        case 672:
            uiOffset = 0x2300320;
            break;
        case 702:
            uiOffset = 0x22C5750;
            break;
        case 900:
            uiOffset = 0x21EFF20;
            break;
        case 1100:
            uiOffset = 0x2116640;
            break;
        case 1202:
            uiOffset = 0x2136E90;
            break;    
        case 1250:
            uiOffset = 0x0; // Missing Offset
            break;
        case 1300:
            uiOffset = 0x0; // Missing Offset
            break;
    }  
    rootvnode = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB:

    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x2382FF8;
            break;
        case 672:
            uiOffset = 0x22BBE80;
            break;
        case 702:
            uiOffset = 0x1B48318;
            break;
        case 900:
            uiOffset = 0x1B946E0;
            break;
        case 1100:
            uiOffset = 0x22D0A98;
            break;
        case 1202:
            uiOffset = 0x1B28538;
            break;    
        case 1250:
            uiOffset = 0x0; // Missing Offset
            break;
        case 1300:
            uiOffset = 0x0; // Missing Offset
            break;
    }  
    allproc = (void *)(cached_kernel_base + uiOffset);

    /*
      AOB:

    */
    uiOffset = 0;
    switch (firmwareVersion) {
        case 505:
            uiOffset = 0x107C610;
            break;
        case 672:
            uiOffset = 0x111E000;
            break;
        case 702:
            uiOffset = 0x1125660;
            break;
        case 900:
            uiOffset = 0x1100310;
            break;
        case 1100:
            uiOffset = 0x1101760;
            break;
        case 1202:
            uiOffset = 0x1102B70;
            break;    
        case 1250:
            uiOffset = 0x0; // Missing Offset
            break;
        case 1300:
            uiOffset = 0x0; // Missing Offset
            break;
    }  
    sysents = (void *)(cached_kernel_base + uiOffset);
}