#include "installer.h"
#include "syscall.h"

extern uint8_t kernelelf[];
extern int32_t kernelelf_size;

extern uint8_t debuggerbin[];
extern int32_t debuggerbin_size;

void ascii_art() {
    printf("\n\n");
    printf("___________                               _____  \n");
    printf("\\_   _____/___________    _____   ____   /  |  | \n");
    printf(" |    __) \\_  __ \\__  \\  /     \\_/ __ \\ /   |  |_\n");
    printf(" |     \\   |  | \\// __ \\|  Y Y  \\  ___//    ^   /\n");
    printf(" \\___  /   |__|  (____  /__|_|  /\\___  >____   | \n");
    printf("     \\/               \\/      \\/     \\/     |__| \n");
    printf("                                                       \n");
}

void patch_kernel() {
    switch (cached_firmware) {
        case 505:
        case 672:
        case 702:
        case 900:
        case 1100:
        case 1202:
        case 1250:
        case 1300:
            break;
        default:
            return;
    }

    uint64_t kernel_base = get_kernel_base();

    cpu_disable_wp();

    int32_t patchJumpOffset = 0;

    // Module: Kernel.elf
    // patch memcpy first
    /*
      AOB: 1F 00 55 48 89 E5 49 89 FA 49 01 D2 49 39 E2 76 17+0F
    
      00000000002714B0 55       push rbp
      00000000002714B1 4889E5   mov rbp, rsp
      00000000002714B4 4989FA   mov r10, rdi
      00000000002714B7 4901D2   add r10, rdx
      00000000002714BA 4939E2   cmp r10, rsp
      
     -00000000002714BD 7617     jbe 0x00000000002714D6
     +00000000002714BD EB17     jmp 0x00000000002714D6
      
      00000000002714BF 4989EA   mov r10, rbp
      00000000002714C2 4983C210 add r10, 0x10
      00000000002714C6 4C39D7   cmp rdi, r10
      00000000002714C9 7D0B     jge 0x00000000002714D6
      00000000002714CB 4889FF   mov rdi, rdi
    */
    uint32_t patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x1EA53D;
            break;
        case 672:
            patchOffset = 0x3C15BD;
            break;
        case 702:
            patchOffset = 0x2F04D;
            break;
        case 900:
            patchOffset = 0x2714BD;
            break;
        case 1100:
            patchOffset = 0x2DDDFD;
            break;
        case 1202:
            patchOffset = 0x2BD48D;
            break;    
        case 1250:
            patchOffset = 0x2BD4CD;
            break;
        case 1300:
            patchOffset = 0x2BD4ED;
            break;
    }
    *(uint8_t *)(kernel_base + patchOffset) = 0xEB;

    // patch sceSblACMgrIsAllowedSystemLevelDebugging
    /*
      AOB: C0 5D C3 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 55 48 89 E5 E8+12

      000000000008BC0C C3                             ret
      000000000008BC0D 31C0                           xor eax, eax
      000000000008BC0F 5D                             pop rbp
      000000000008BC10 C3                             ret
      000000000008BC11 909090909090909090909090909090 nop:15
      
     -000000000008BC20 55                             push rbp
     -000000000008BC21 4889E5                         mov rbp, rsp
     -000000000008BC24 E807C12800                     call 0x0000000000317D30
      
     +000000000008BC20 31C0                           xor eax, eax
     +000000000008BC22 FFC0                           inc eax
     +000000000008BC24 C3                             ret 

      000000000008BC29 31C9                           xor ecx, ecx
      000000000008BC2B 83F801                         cmp eax, 1
      000000000008BC2E 0F94C1                         sete cl
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x11730;
            break;
        case 672:
            patchOffset = 0x233BD0;
            break;
        case 702:
            patchOffset = 0x1CB880;
            break;
        case 900:
            patchOffset = 0x8BC20;
            break;
        case 1100:
            patchOffset = 0x3D0DE0;
            break;
        case 1202:
            patchOffset = 0x3B2CD0;
            break;
        case 1250:
            patchOffset = 0x3B2D10;
            break;
        case 1300:
            patchOffset = 0x3B2D30;
            break;
    }
    memcpy((void *)(kernel_base + patchOffset), "\x31\xC0\xFF\xC0\xC3", 5);

    // patch sceSblACMgrHasMmapSelfCapability
    /*
      AOB: 55 48 89 E5 48 8B 47 68 48 C1 E8 3A

      000000000008BC86 4883C408 add rsp, 8
      000000000008BC8A 5B       pop rbx
      000000000008BC8B 5D       pop rbp
      000000000008BC8C C3       ret
      000000000008BC8D 909090   nop:3
      
     -000000000008BC90 55       push rbp
     -000000000008BC91 4889E5   mov rbp, rsp
     -000000000008BC94 488B4768 mov rax, [rdi+0x68]

     +000000000008BC90 31C0     xor eax, eax
     +000000000008BC91 FFC0     inc eax
     +000000000008BC94 C3       ret 
     
      000000000008BC98 48C1E83A shr rax, 0x3A
      000000000008BC9C 83E001   and eax, 1
      000000000008BC9F 5D       pop rbp
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x117B0;
            break;
        case 672:
            patchOffset = 0x233C40;
            break;
        case 702:
            patchOffset = 0x1CB8F0;
            break;
        case 900:
            patchOffset = 0x8BC90;
            break;
        case 1100:
            patchOffset = 0x3D0E50;
            break;
        case 1202:
            patchOffset = 0x3B2D40;
            break;
        case 1250:
            patchOffset = 0x3B2D00;
            break;
        case 1300:
            patchOffset = 0x3B2DA0;
            break;
    }
    memcpy((void *)(kernel_base + patchOffset), "\x31\xC0\xFF\xC0\xC3", 5);

    // patch sceSblACMgrIsAllowedToMmapSelf
    /*
      AOB: 55 48 89 E5 F6 47 17

      000000000008BC98 48C1E83A
      000000000008BC9C 83E001
      000000000008BC9F 5D
      000000000008BCA0 C3
      000000000008BCA1 909090909090909090909090909090
      
     -000000000008BCB0 55
     -000000000008BCB1 4889E5
     -000000000008BCB4 F6471704

     +000000000008BCB0 31C0     xor eax, eax
     +000000000008BCB1 FFC0     inc eax
     +000000000008BCB4 C3       ret 

      000000000008BCB8 740B
      000000000008BCBA F6462B08
      000000000008BCBE B801000000
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x117C0;
            break;
        case 672:
            patchOffset = 0x233C50;
            break;
        case 702:
            patchOffset = 0x1CB910;
            break;
        case 900:
            patchOffset = 0x8BCB0;
            break;
        case 1100:
            patchOffset = 0x3D0E70;
            break;
        case 1202:
            patchOffset = 0x3B2D60;
            break;
        case 1250:
            patchOffset = 0x3B2DA0;
            break;
        case 1300:
            patchOffset = 0x3B2DC0;
            break;
    }
    memcpy((void *)(kernel_base + patchOffset), "\x31\xC0\xFF\xC0\xC3", 5);

    // disable sysdump_perform_dump_on_fatal_trap
    // will continue execution and give more information on crash, such as rip
    /*
      AOB: 55 48 89 E5 41 56 53 80 3D * * * 02 01

      0000000000767E17 E8D495B0FF       call 0x00000000002713F0
      0000000000767E1C E928FFFFFF       jmp 0x0000000000767D49
      0000000000767E21 E86AFFF5FF       call 0x00000000006C7D90
      0000000000767E26 0F0B             ud2
      0000000000767E28 9090909090909090 nop:8

     -0000000000767E30 55               push rbp
     +0000000000767E30 C3               ret
     
      0000000000767E31 4889E5           mov rbp, rsp
      0000000000767E34 4156             push r14
      0000000000767E36 53               push rbx
      0000000000767E37 803D2A02010201   cmp byte ptr [rip+0x201022A], 1
      0000000000767E3E 0F85FE010000     jne 0x0000000000768042
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x7673E0;
            break;
        case 672:
            patchOffset = 0x784120;
            break;
        case 702:
            patchOffset = 0x7889E0;
            break;
        case 900:
            patchOffset = 0x767E30;
            break;
        case 1100:
            patchOffset = 0x76D210;
            break;
        case 1202:
            patchOffset = 0x76B7F0;
            break;
        case 1250:
            patchOffset = 0x76B8B0;
            break;
        case 1300:
            patchOffset = 0x76BA30;
            break;
    }
    *(uint8_t *)(kernel_base + patchOffset) = 0xC3;

    // self patches
    /*
      AOB: 85 C0 0F 84 * * * * 48 8B BD B8-05

      000000000016803C 4885C0         test rax, rax
      000000000016803F 480F45D0       cmovne rdx, rax
      0000000000168043 488B85B8FEFFFF mov rax, [rbp-0x148]
      000000000016804A 4883C658       add rsi, 0x58
      000000000016804E 8B7840         mov edi, [rax+0x40]
      
     -0000000000168051 E8AAC64D00     call 0x0000000000644700
     +0000000000168051 31C0           xor eax, eax
     +0000000000168053 909090         nop:3 
     
      0000000000168056 85C0           test eax, eax
      0000000000168058 0F8477010000   je 0x00000000001681D5
      000000000016805E 488BBDB8FEFFFF mov rdi, [rbp-0x148]
      0000000000168065 89C3           mov ebx, eax
      0000000000168067 E854861300     call 0x00000000002A06C0
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x13F03F;
            break;
        case 672:
            patchOffset = 0xAD2E4;
            break;
        case 702:
            patchOffset = 0x1D40BB;
            break;
        case 900:
            patchOffset = 0x168051;
            break;
        case 1100:
            patchOffset = 0x157F91;
            break;
        case 1202:
            patchOffset = 0x1FC441;
            break;
        case 1250:
            patchOffset = 0x1FC481;
            break;
        case 1300:
            patchOffset = 0x1FC4A1;
            break;
    }
    memcpy((void *)(kernel_base + patchOffset), "\x31\xC0\x90\x90\x90", 5);

    // patch vm_map_protect check
    /*
      AOB: 0F 85 * * * * 49 8B 7D 48 48

      0000000000080B7A 0F44FA           cmove edi, edx
      0000000000080B7D 40F6C601         test sil, 1
      0000000000080B81 410F45F8         cmovne edi, r8d
      0000000000080B85 4420F7           and dil, r14b
      0000000000080B88 4438F7           cmp dil, r14b

     -0000000000080B8B 0F8552060000     jne 0x00000000000811E3
     +0000000000080B8B 909090909090     nop:6

      0000000000080B91 498B7D48         mov rdi, [r13+0x48]
      0000000000080B95 4885FF           test rdi, rdi
      0000000000080B98 7486             je 0x0000000000080B20
      0000000000080B9A 6683BF8600000000 cmp word ptr [rdi+0x86], 0
      0000000000080BA2 0F8978FFFFFF     jns 0x0000000000080B20
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x1A3C08;
            break;
        case 672:
            patchOffset = 0x451DB8;
            break;
        case 702:
            patchOffset = 0x264C08;
            break;
        case 900:
            patchOffset = 0x80B8B;
            break;
        case 1100:
            patchOffset = 0x35C8EC;
            break;
        case 1202:
            patchOffset = 0x2FC0EC;
            break;
        case 1250:
            patchOffset = 0x2FC12C;
            break;
        case 1300:
            patchOffset = 0x2FC14C;
            break;
    }
    memcpy((void *)(kernel_base + patchOffset), "\x90\x90\x90\x90\x90\x90", 6);

    // patch ptrace, thanks 2much4u
    /*
      AOB: 77 * 48 B8 36 

      000000000041F4CD E89EFCECFF           call 0x00000000002EF170
      000000000041F4D2 8B85C8FEFFFF         mov eax, [rbp-0x138]
      000000000041F4D8 448BBDD4FEFFFF       mov r15d, [rbp-0x12C]
      000000000041F4DF 4189C4               mov r12d, eax
      000000000041F4E2 83F82A               cmp eax, 0x2A
      
     -000000000041F4E5 771C                 ja 0x000000000041F503
     +000000000041F4E5 EB1C                 jmp 0x000000000041F503
     
      000000000041F4E7 48B8361000007E020000 mov rax, 0x27E00001036
      000000000041F4F1 4C0FA3E0             bt rax, r12
      000000000041F4F5 0F8302020000         jae 0x000000000041F6FD
      000000000041F4FB 85DB                 test ebx, ebx
      000000000041F4FD 0F8419020000         je 0x000000000041F71C
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x30D9AA;
            break;
        case 672:
            patchOffset = 0x10F879;
            break;
        case 702:
            patchOffset = 0x448D5;
            break;
        case 900:
            patchOffset = 0x41F4E5;
            break;
        case 1100:
            patchOffset = 0x384285;
            break;
        case 1202:
            patchOffset = 0x366985;
            break;
        case 1250:
            patchOffset = 0x3669C5;
            break;
        case 1300:
            patchOffset = 0x3669E5;
            break;
    }
    *(uint8_t *)(kernel_base + patchOffset) = 0xEB;


    // remove all these bullshit checks from ptrace, by golden
    /*
      AOB: 48 8B 41 08 44 89

      000000000041F9B8 4183FF0B               cmp r15d, 0xB
      000000000041F9BC 41BC10000000           mov r12d, 0x10
      000000000041F9C2 750D                   jne 0x000000000041F9D1
      000000000041F9C4 4981BE30040000FFFFFF7F cmp qword ptr [r14+0x430], 0x7FFFFFFF
      000000000041F9CF 776D                   ja 0x000000000041FA3E

     -000000000041F9D1 488B4108               mov rax, [rcx+8] 
     -000000000041F9D5 4489C3                 mov ebx, r8d
     +000000000041F9D1 E97C020000             jmp 0x41fc52

      000000000041F9D8 488B7840               mov rdi, [rax+0x40]
      000000000041F9DC E85FBBC6FF             call 0x000000000008B540
      000000000041F9E1 418B8EA8000000         mov ecx, [r14+0xA8]
      000000000041F9E8 4189D8                 mov r8d, ebx

      AOB Jump Target: 44 89 FA E9 EE      
      000000000041FC3E 4C89F7       mov rdi, r14
      000000000041FC41 31F6         xor esi, esi
      000000000041FC43 B9DD050000   mov ecx, 0x5DD
      000000000041FC48 E863F2ECFF   call 0x00000000002EEEB0
      000000000041FC4D E9E80E0000   jmp 0x0000000000420B3A
    ->000000000041FC52 4489FA       mov edx, r15d
      000000000041FC55 E9EEFCFFFF   jmp 0x000000000041F948
      000000000041FC5A 4C89F8       mov rax, r15
      000000000041FC5D 83F816       cmp eax, 0x16
      000000000041FC60 0F841D080000 je 0x0000000000420483
      000000000041FC66 83F815       cmp eax, 0x15
    */
    patchOffset = 0;
    patchJumpOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x30DE01;
            patchJumpOffset = 0xD000;
            break;
        case 672:
            patchOffset = 0x10FD22;
            patchJumpOffset = 0xE202;
            break;
        case 702:
            patchOffset = 0x44DAF;
            patchJumpOffset = 0x7C02;
            break;
        case 900:
            patchOffset = 0x41F9D1;
            patchJumpOffset = 0x7C02;
            break;
        case 1100:
            patchOffset = 0x384771;
            patchJumpOffset = 0x7C02;
            break;
        case 1202:
            patchOffset = 0x366E71;
            patchJumpOffset = 0x7C02;
            break;
        case 1250:
            patchOffset = 0x366EB1;
            patchJumpOffset = 0x7C02;
            break;
        case 1300:
            patchOffset = 0x366ED1;
            patchJumpOffset = 0x7C02;
            break;
    }
    *(uint8_t *)(kernel_base + patchOffset) = 0xE9;
    *(int32_t *)(kernel_base + patchOffset + 1) = patchJumpOffset;


    // patch ASLR, thanks 2much4u
    /*
      AOB: E9 * * * * 31 C0 08 C3+9 

      000000000005F80F 488D0DA3937100     lea rcx, [rip+0x7193A3]
      000000000005F816 BEAF050000         mov esi, 0x5AF
      000000000005F81B E94A010000         jmp 0x000000000005F96A
      000000000005F820 31C0               xor eax, eax
      000000000005F822 08C3               or bl, al

     -000000000005F824 740B               je 0x000000000005F831
     +000000000005F824 9090               nop:2
     
      000000000005F826 49C744243800004000 mov qword ptr [r12+0x38], 0x400000
      000000000005F82F EB46               jmp 0x000000000005F877
      000000000005F831 498B3C24           mov rdi, [r12]
      000000000005F835 E806F1FEFF         call 0x000000000004E940
      000000000005F83A 498B942400020000   mov rdx, [r12+0x200]      
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x194875;
            break;
        case 672:
            patchOffset = 0x3CECE1;
            break;
        case 702:
            patchOffset = 0xC1F9A;
            break;
        case 900:
            patchOffset = 0x5F824;
            break;
        case 1100:
            patchOffset = 0x3B11A4;
            break;
        case 1202:
            patchOffset = 0x477C54;
            break;
        case 1250:
            patchOffset = 0x477C94;
            break;
        case 1300:
            patchOffset = 0x477CB4;
            break;
    }
    if ((cached_firmware == 672) || (cached_firmware == 702)) {
        *(uint8_t *)(kernel_base + patchOffset) = 0xEB; 
    } else {
        *(uint16_t *)(kernel_base + patchOffset) = 0x9090;
    }

    // patch kmem_alloc
    /*
      AOB: FA 41 B9 03 00 00 00+03

      000000000037BF29 4883EC08     sub rsp, 8
      000000000037BF2D 4C8D0419     lea r8, [rcx+rbx]
      000000000037BF31 4C89F7       mov rdi, r14
      000000000037BF34 4C89E6       mov rsi, r12
      000000000037BF37 4C89FA       mov rdx, r15

     -000000000037BF3A 41B903000000 mov r9d, 3
     +000000000037BF3A 41B907000000 mov r9d, 7

      000000000037BF40 6A00         push 0
      000000000037BF42 50           push rax
      000000000037BF43 6A03         push 3
      000000000037BF45 E8360ED0FF   call 0x000000000007CD80
      000000000037BF4A 4883C420     add rsp, 0x20
    */ 
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0xFCD48;
            break;
        case 672:
            patchOffset = 0x2507F5;
            break;
        case 702:
            patchOffset = 0x1171BE;
            break;
        case 900:
            patchOffset = 0x37BF3C;
            break;
        case 1100:
            patchOffset = 0x245EDC;
            break;
        case 1202:
            patchOffset = 0x465AAC;
            break;
        case 1250:
            patchOffset = 0x465AEC;
            break;
        case 1300:
            patchOffset = 0x465B0C;
            break;
    }
    *(uint8_t *)(kernel_base + patchOffset) = VM_PROT_ALL;
    /*
      AOB: 6A 03 E8 * * * * 48 83 C4 20 85 C0 74 3F+1

      000000000037BF34 4C89E6         mov rsi, r12
      000000000037BF37 4C89FA         mov rdx, r15
      000000000037BF3A 41B903000000   mov r9d, 3
      000000000037BF40 6A00           push 0
      000000000037BF42 50             push rax
      
     -000000000037BF43 6A03           push 3
     +000000000037BF43 6A03           push 7

      000000000037BF45 E8360ED0FF     call 0x000000000007CD80
      000000000037BF4A 4883C420       add rsp, 0x20
      000000000037BF4E 85C0           test eax, eax
      000000000037BF50 743F           je 0x000000000037BF91
      000000000037BF52 488D3D37B28401 lea rdi, [rip+0x184B237]
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0xFCD56;
            break;
        case 672:
            patchOffset = 0x250803;
            break;
        case 702:
            patchOffset = 0x1171C6;
            break;
        case 900:
            patchOffset = 0x37BF44;
            break;
        case 1100:
            patchOffset = 0x245EE4;
            break;
        case 1202:
            patchOffset = 0x465AB4;
            break;
        case 1250:
            patchOffset = 0x465AF4;
            break;
        case 1300:
            patchOffset = 0x465B14;
            break;
    }
    *(uint8_t *)(kernel_base + patchOffset) = VM_PROT_ALL;

    // patch kernel elf loading, thanks to DeathRGH
    /*
      AOB: 75 * 4C 89 D7

      0000000000081367 2422       and al, 0x22
      0000000000081369 742D       je 0x0000000000081398
      000000000008136B 418B442458 mov eax, [r12+0x58]
      0000000000081370 83E024     and eax, 0x24
      0000000000081373 83F824     cmp eax, 0x24

     -0000000000081376 7520       jne 0x0000000000081398
     +0000000000081376 EB20       jmp 0x0000000000081398
      
      0000000000081378 4C89D7     mov rdi, r10
      000000000008137B 4C89D6     mov rsi, r10
      000000000008137E 4C89E2     mov rdx, r12
      0000000000081381 4C89E1     mov rcx, r12
      0000000000081384 4531C0     xor r8d, r8d
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x1A439D;
            break;
        case 672:
            patchOffset = 0x45255D;
            break;
        case 702:
            patchOffset = 0x2653D6;
            break;
        case 900:
            patchOffset = 0x81376;
            break;
        case 1100:
            patchOffset = 0x35D221;
            break;
        case 1202:
            patchOffset = 0x2FCA21;
            break;
        case 1250:
            patchOffset = 0x2FCA61;
            break;
        case 1300:
            patchOffset = 0x2FCA81;
            break;
    }
    *(uint8_t *)(kernel_base + patchOffset) = 0xEB;

    // patch copyin/copyout to allow userland + kernel addresses in both params
    /*
      AOB: 77 47 48 B8 
                                            
      00000000002716E2 4889F8               mov rax, rdi 
      00000000002716E5 4801D0               add rax, rdx 
      00000000002716E8 7256                 jb 0x0000000000271740 
      00000000002716EA 48B90000000000800000 mov rcx, 0x800000000000 
      00000000002716F4 4839C8               cmp rax, rcx 

     -00000000002716F7 7747                 ja 0x0000000000271740 
     +00000000002716F7 9090                 nop:2
     
      00000000002716F9 48B8FFFFFFFFFF7F0000 mov rax, 0x7FFFFFFFFFFF 
      0000000000271703 4821C7               and rdi, rax 
      0000000000271706 4887FE               xchg rdi, rsi 
      0000000000271709 4889D1               mov rcx, rdx 
      000000000027170C 88C8                 mov al, cl
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x1EA767;
            break;
        case 672:
            patchOffset = 0x3C17F7;
            break;
        case 702:
            patchOffset = 0x2F287;
            break;
        case 900:
            patchOffset = 0x2716F7;
            break;
        case 1100:
            patchOffset = 0x2DE037;
            break;
        case 1202:
            patchOffset = 0x2BD6C7;
            break;
        case 1250:
            patchOffset = 0x2BD707;
            break;
        case 1300:
            patchOffset = 0x2BD727;
            break;
    }
    *(uint16_t *)(kernel_base + patchOffset) = 0x9090;

    /*
      AOB: 48 21 C7 48 87

      00000000002716E8 7256                 jb 0x0000000000271740
      00000000002716EA 48B90000000000800000 mov rcx, 0x800000000000
      00000000002716F4 4839C8               cmp rax, rcx
      00000000002716F7 7747                 ja 0x0000000000271740
      00000000002716F9 48B8FFFFFFFFFF7F0000 mov rax, 0x7FFFFFFFFFFF

     -0000000000271703 4821C7               and rdi, rax
     +0000000000271703 909090               nop:3

      0000000000271706 4887FE               xchg rdi, rsi
      0000000000271709 4889D1               mov rcx, rdx
      000000000027170C 88C8                 mov al, cl
      000000000027170E 48C1E903             shr rcx, 3
      0000000000271712 FC                   cld
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 672:
            patchOffset = 0x3C1803;
            break;
        case 702:
            patchOffset = 0x2F293;
            break;
        case 900:
            patchOffset = 0x271703;
            break;
        case 1100:
            patchOffset = 0x2DE043;
            break;
        case 1202:
            patchOffset = 0x2BD6D3;
            break;
        case 1250:
            patchOffset = 0x2BD713;
            break;
        case 1300:
            patchOffset = 0x2BD733;
            break;
    }
    if (patchOffset != 0) {
        memcpy((void *)(kernel_base + patchOffset), "\x90\x90\x90", 3);
    }

    /*
      AOB: 77 5C 48 B8

      00000000002715ED 4889F0               mov rax, rsi
      00000000002715F0 4801D0               add rax, rdx
      00000000002715F3 726B                 jb 0x0000000000271660
      00000000002715F5 48B90000000000800000 mov rcx, 0x800000000000
      00000000002715FF 4839C8               cmp rax, rcx

     -0000000000271602 775C                 ja 0x0000000000271660
     +0000000000271602 9090                 nop:2

      0000000000271604 48B8FFFFFFFFFF7F0000 mov rax, 0x7FFFFFFFFFFF
      000000000027160E 4821C6               and rsi, rax
      0000000000271611 488B0510E2EA00       mov rax, [rip+0xEAE210]
      0000000000271618 4839C7               cmp rdi, rax
      000000000027161B 7314                 jae 0x0000000000271631
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x1EA682;
            break;
        case 672:
            patchOffset = 0x3C1702;
            break;
        case 702:
            patchOffset = 0x2F192;
            break;
        case 900:
            patchOffset = 0x271602;
            break;
        case 1100:
            patchOffset = 0x2DDF42;
            break;
        case 1202:
            patchOffset = 0x2BD5D2;
            break;
        case 1250:
            patchOffset = 0x2BD612;
            break;
        case 1300:
            patchOffset = 0x2BD632;
            break;
    }
    *(uint16_t *)(kernel_base + patchOffset) = 0x9090;
    /*
      AOB: 48 21 C6 48 8B

      00000000002715F3 726B                 jb 0x0000000000271660
      00000000002715F5 48B90000000000800000 mov rcx, 0x800000000000
      00000000002715FF 4839C8               cmp rax, rcx
      0000000000271602 775C                 ja 0x0000000000271660
      0000000000271604 48B8FFFFFFFFFF7F0000 mov rax, 0x7FFFFFFFFFFF

     -000000000027160E 4821C6               and rsi, rax
     +000000000027160E 909090               nop:3

      0000000000271611 488B0510E2EA00       mov rax, [rip+0xEAE210]
      0000000000271618 4839C7               cmp rdi, rax
      000000000027161B 7314                 jae 0x0000000000271631
      000000000027161D 4889F9               mov rcx, rdi
      0000000000271620 4801D1               add rcx, rdx
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 672:
            patchOffset = 0x3C170E;
            break;
        case 702:
            patchOffset = 0x2F19E;
            break;
        case 900:
            patchOffset = 0x27160E;
            break;
        case 1100:
            patchOffset = 0x2DDF4E;
            break;
        case 1202:
            patchOffset = 0x2BD5DE;
            break;
        case 1250:
            patchOffset = 0x2BD61E;
            break;
        case 1300:
            patchOffset = 0x2BD63E;
            break;
    }
    if (patchOffset != 0) {
        memcpy((void *)(kernel_base + patchOffset), "\x90\x90\x90", 3);
    }
    // patch copyinstr
    /*
      AOB: 76 46 48 B9 

      0000000000271B7F 65488B0C2520000000   mov rcx, gs:[0x20]
      0000000000271B88 488B05B9DCEA00       mov rax, [rip+0xEADCB9]
      0000000000271B8F 488981D0000000       mov [rcx+0xD0], rax
      0000000000271B96 48B80000000000800000 mov rax, 0x800000000000
      0000000000271BA0 4829F0               sub rax, rsi

     -0000000000271BA3 7646                 jbe 0x0000000000271BEB
     +0000000000271BA3 9090                 nop:2

      0000000000271BA5 48B9FFFFFFFFFF7F0000 mov rcx, 0x7FFFFFFFFFFF
      0000000000271BAF 4821CE               and rsi, rcx
      0000000000271BB2 4839D0               cmp rax, rdx
      0000000000271BB5 7306                 jae 0x0000000000271BBD
      0000000000271BB7 4889C2               mov rdx, rax
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x1EAB93;
            break;
        case 672:
            patchOffset = 0x3C1CA3;
            break;
        case 702:
            patchOffset = 0x2F733;
            break;
        case 900:
            patchOffset = 0x271BA3;
            break;
        case 1100:
            patchOffset = 0x2DE4E3;
            break;
        case 1202:
            patchOffset = 0x2BDB73;
            break;
        case 1250:
            patchOffset = 0x2BDBB3;
            break;
        case 1300:
            patchOffset = 0x2BDBD3;
            break;
    }
    *(uint16_t *)(kernel_base + patchOffset) = 0x9090;
    /*
      AOB: 73 09 48 C7 C0

      0000000000271BCC 48FFCA                 dec rdx
      0000000000271BCF 31C0                   xor eax, eax
      0000000000271BD1 EB1F                   jmp 0x0000000000271BF2
      0000000000271BD3 48B80000000000800000   mov rax, 0x800000000000
      0000000000271BDD 4839C6                 cmp rsi, rax

     -0000000000271BE0 7309                   jae 0x0000000000271BEB
     +0000000000271BE0 9090                   nop:2

      0000000000271BE2 48C7C03F000000         mov rax, 0x3F
      0000000000271BE9 EB07                   jmp 0x0000000000271BF2
      0000000000271BEB 48C7C00E000000         mov rax, 0xE
      0000000000271BF2 65488B0C2520000000     mov rcx, gs:[0x20]
      0000000000271BFB 48C781D000000000000000 mov qword ptr [rcx+0xD0], 0
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x1EABC3;
            break;
        case 672:
            patchOffset = 0x3C1CE0;
            break;
        case 702:
            patchOffset = 0x2F770;
            break;
        case 900:
            patchOffset = 0x271BE0;
            break;
        case 1100:
            patchOffset = 0x2DE520;
            break;
        case 1202:
            patchOffset = 0x2BDBB0;
            break;
        case 1250:
            patchOffset = 0x2BDBF0;
            break;
        case 1300:
            patchOffset = 0x2BDC10;
            break;
    }
    *(uint16_t *)(kernel_base + patchOffset) = 0x9090;
    /*
      AOB: 48 21 CE 48 39 D0

      0000000000271B8F 488981D0000000       mov [rcx+0xD0], rax
      0000000000271B96 48B80000000000800000 mov rax, 0x800000000000
      0000000000271BA0 4829F0               sub rax, rsi
      0000000000271BA3 7646                 jbe 0x0000000000271BEB
      0000000000271BA5 48B9FFFFFFFFFF7F0000 mov rcx, 0x7FFFFFFFFFFF

     -0000000000271BAF 4821CE               and rsi, rcx
     +0000000000271BAF 909090               nop:3

      0000000000271BB2 4839D0               cmp rax, rdx
      0000000000271BB5 7306                 jae 0x0000000000271BBD
      0000000000271BB7 4889C2               mov rdx, rax
      0000000000271BBA 4989C0               mov r8, rax
      0000000000271BBD 48FFC2               inc rdx
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 672:
            patchOffset = 0x3C1CE0;
            break;
        case 702:
            patchOffset = 0x2F73F;
            break;
        case 900:
            patchOffset = 0x271BAF;
            break;
        case 1100:
            patchOffset = 0x2DE4EF;
            break;
        case 1202:
            patchOffset = 0x2BDB7F;
            break;
        case 1250:
            patchOffset = 0x2BDBBF;
            break;
        case 1300:
            patchOffset = 0x2BDBDF;
            break;
    }
    if (patchOffset != 0) {
        memcpy((void *)(kernel_base + patchOffset), "\x90\x90\x90", 3);
    }
    
    // patch to remove vm_fault: fault on nofault entry, addr %llx
    /*
      AOB: 48 8B 85 50 FF FF FF 48 8B BD-06

      0000000000152951 4885F6         test rsi, rsi
      0000000000152954 740D           je 0x0000000000152963
      0000000000152956 80BE850000000B cmp byte ptr [rsi+0x85], 0xB
      000000000015295D 0F8491140000   je 0x0000000000153DF4
      0000000000152963 F6C110         test cl, 0x10

     -0000000000152966 0F85B3170000   jne 0x000000000015411F
     +0000000000152966 909090909090   nop:6
     
      000000000015296C 488B8550FFFFFF mov rax, [rbp-0xB0]
      0000000000152973 488BBD40FFFFFF mov rdi, [rbp-0xC0]
      000000000015297A 4C89E2         mov rdx, r12
      000000000015297D B952010000     mov ecx, 0x152
      0000000000152982 31F6           xor esi, esi
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x2A4EB3;
            break;
        case 672:
            patchOffset = 0xBC8F6;
            break;
        case 702:
            patchOffset = 0x2BF756;
            break;
        case 900:
            patchOffset = 0x152966;
            break;
        case 1100:
            patchOffset = 0x31E8A6;
            break;
        case 1202:
            patchOffset = 0x1E20A6;
            break;
        case 1250:
            patchOffset = 0x1E20E6;
            break;
        case 1300:
            patchOffset = 0x1E2106;
            break;
    }
    memcpy((void *)(kernel_base + patchOffset), "\x90\x90\x90\x90\x90\x90", 6);

    // patch 2mpage budget kernel panic after injecting an elf and quitting a newer game
    /*
      AOB (7.00):  3E 0F 85 * * * * E8+01
      AOB (9.00+): 0F 85 * * * * E8 * * * * 4C 8B

      00000000000884AA 53             push rbx
      00000000000884AB 488B3D4E7BAB01 mov rdi, [rip+0x1AB7B4E]
      00000000000884B2 4885FF         test rdi, rdi
      00000000000884B5 7E7A           jle 0x0000000000088531
      00000000000884B7 483B3D527BAB01 cmp rdi, [rip+0x1AB7B52]

     -00000000000884BE 0F8598000000   jne 0x000000000008855C
     +00000000000884BE 909090909090   nop:6

      00000000000884C4 E8E7DF3700     call 0x00000000004064B0
      00000000000884C9 4C8B25307BAB01 mov r12, [rip+0x1AB7B30]
      00000000000884D0 4C8D3D7107AB01 lea r15, [rip+0x1AB0771]
      00000000000884D7 4C8D35AA436F00 lea r14, [rip+0x6F43AA]
      00000000000884DE B969010000     mov ecx, 0x169 
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 672:
            patchOffset = 0x459763;
            break;
        case 702:
            patchOffset = 0x26C5F3;
            break;
        case 900:
            patchOffset = 0x884BE;
            break;
        case 1100:
            patchOffset = 0x36434E;
            break;
        case 1202:
            patchOffset = 0x303B4E;
            break;
        case 1250:
            patchOffset = 0x303B8E;
            break;
        case 1300:
            patchOffset = 0x303BAE;
            break;
    }
    if (patchOffset != 0) {
        memcpy((void *)(kernel_base + patchOffset), "\x90\x90\x90\x90\x90\x90", 6);
    }
    
    // patch sys_virtual_query check for pages flagged as system
    /*
      AOB: 48 89 D8 48 C1 E8 2F 75 * 48 8D

      00000000001686CE 4489BD7CFFFFFF     mov [rbp-0x84], r15d
      00000000001686D5 48899D70FFFFFF     mov [rbp-0x90], rbx
      00000000001686DC 4C8BBD68FFFFFF     mov r15, [rbp-0x98]
      00000000001686E3 488B5840           mov rbx, [rax+0x40]
      00000000001686E7 660F1F840000000000 nop word ptr [rax+rax]

     -00000000001686F0 4889D8             mov rax, rbx
     -00000000001686F3 48C1E82F           shr rax, 0x2F
     +00000000001686F0 E981000000         jmp 0x168776

      00000000001686F7 7566               jne 0x000000000016875F
      00000000001686F9 488D7B08           lea rdi, [rbx+8]
      00000000001686FD E84E82E9FF         call 0x0000000000000950
      0000000000168702 4889DF             mov rdi, rbx
      
      AOB Jump Target: 31 DB 48 8D 35 * * * * 4C 89 FF BA * * 00 00 E8 * * * * 48 8D 55 80+2
      000000000016875F 498B4608             mov rax, [r14+8]
      0000000000168763 4531E4               xor r12d, r12d
      0000000000168766 81B8400B0000FFFFFF04 cmp dword ptr [rax+0xB40], 0x4FFFFFF
      0000000000168770 410F97C4             seta r12b
      0000000000168774 31DB                 xor ebx, ebx
    ->0000000000168776 488D35FFDE6200       lea rsi, [rip+0x62DEFF]
      000000000016877D 4C89FF               mov rdi, r15
      0000000000168780 BA59090000           mov edx, 0x959
      0000000000168785 E8F633F1FF           call 0x000000000007BB80
      000000000016878A 488D5580             lea rdx, [rbp-0x80]
      000000000016878E 4C89FF               mov rdi, r15
    */
    patchOffset = 0;
    patchJumpOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x13FA0B;
            patchJumpOffset = 0xA9;
            break;
        case 672:
            patchOffset = 0xAD9C4;
            patchJumpOffset = 0xC9;
            break;
        case 702:
            patchOffset = 0x1D4750;
            patchJumpOffset = 0x81;
            break;
        case 900:
            patchOffset = 0x1686F0;
            patchJumpOffset = 0x81;
            break;
        case 1100:
            patchOffset = 0x158500;
            patchJumpOffset = 0x81;
            break;
        case 1202:
            patchOffset = 0x1FC9B0;
            patchJumpOffset = 0x81;
            break;
        case 1250:
            patchOffset = 0x1FC9F0;
            patchJumpOffset = 0x81;
            break;
        case 1300:
            patchOffset = 0x1FCA10;
            patchJumpOffset = 0x81;
            break;
    }
    *(uint8_t *)(kernel_base + patchOffset) = 0xE9;
    *(int32_t *)(kernel_base + patchOffset + 1) = patchJumpOffset;

    // patch blkno spam caused by aio bug (5.05 only)
    /*
      AOB: 

      
    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 505:
            patchOffset = 0x68F188;
            break;
    }
    if (patchOffset != 0) {
        memcpy((void *)(kernel_base + patchOffset), "\x90\x90\x90\x90\x90", 5);
    }
    
    // patch for panic %lx bytes 2MB page is reserved, but used %#lx bytes (9.00 only)
    /*
      AOB: B8 00 00 00 00 0F 84 * * * * E8+05 

      000000000015658E 4C8B75B8       mov r14, [rbp-0x48]
      0000000000156592 4D85F6         test r14, r14
      0000000000156595 7440           je 0x00000000001565D7
      0000000000156597 4D39F7         cmp r15, r14
      000000000015659A B800000000     mov eax, 0

     -000000000015659F 0F8452020000   je 0x00000000001567F7
     +000000000015659F E953020000     jmp 0x00000000001567F7
     +00000000001565A4 90             nop

      00000000001565A5 E8E61E6100     call 0x0000000000768490
      00000000001565AA 488D3DF4FFFFFF lea rdi, [rip-0xC]
      00000000001565B1 4C89F6         mov rsi, r14
      00000000001565B4 4C89FA         mov rdx, r15
      00000000001565B7 E8C4256100     call 0x0000000000768B80
    */
    patchOffset = 0;
    switch (cached_firmware) {
//        case 702:
//            patchOffset = 0x2C33DD;
//            break;
        case 900:
            patchOffset = 0x15659F;
            break;            
//        case 1250:
//            patchOffset = 0x1E5D4F;
//            break;
//        case 1300:
//            patchOffset = 0x1E5D6F;
//            break;            
    }
    if (patchOffset != 0) {
        memcpy((void *)(kernel_base + patchOffset), "\xE9\x53\x02\x00\x00\x90", 6);
    }
    
    // missing patch from goldhen so we add it here (11.00 only)
    // allow allocating executable memory
    /*
      AOB: 

    */
    patchOffset = 0;
    switch (cached_firmware) {
        case 1100:
            patchOffset = 0x15626A;
            break;
    }
    if (patchOffset != 0) {
        memcpy((void *)(kernel_base + patchOffset), "\x37\x41\xB2\x37", 4);
    }    
    
    cpu_enable_wp();
}

int patch_shellcore() {
    struct proc *p = proc_find_by_name("SceShellCore");
    if (!p) {
        printf("[Frame4] <patch_shellcore> could not find SceShellCore process!\n");
        return 1;
    }

    printf("[Frame4] <patch_shellcore> SceShellCore found, pid = %i\n", p->pid);

    struct vmspace *vm;
    struct vm_map *map;
    struct vm_map_entry *entry;
    struct sys_proc_vm_map_args args;

    memset(&args, NULL, sizeof(struct sys_proc_vm_map_args));

    vm = p->p_vmspace;
    map = &vm->vm_map;
    args.num = map->nentries;

    uint64_t size = args.num * sizeof(struct proc_vm_map_entry);
    args.maps = (struct proc_vm_map_entry *)malloc(size, M_TEMP, 2);

    vm_map_lock_read(map);
    
    if (vm_map_lookup_entry(map, NULL, &entry)) {
        vm_map_unlock_read(map);
        return 1;
    }

    for (int i = 0; i < args.num; i++) {
        args.maps[i].start = entry->start;
        args.maps[i].end = entry->end;
        args.maps[i].offset = entry->offset;
        args.maps[i].prot = entry->prot & (entry->prot >> 8);
        memcpy(args.maps[i].name, entry->name, sizeof(args.maps[i].name));
            
        if (!(entry = entry->next)) {
            break;
        }
    }

    vm_map_unlock_read(map);

    uint64_t shellcore_base = args.maps[1].start;
    
    uint64_t mountPatchOffset = 0;
    uint64_t mountPatchOffset2 = 0;
    uint64_t disableCoreDumpPatch = 0;
    uint64_t fwCheckPatch = 0;

    switch (cached_firmware) {
        case 505:
            mountPatchOffset = 0x31CA2A;
            // mountPatchOffset2 (check did not exist on 5.05 yet)
            fwCheckPatch = 0x3CCB79;
            disableCoreDumpPatch = 0x2E965E;
            break;
        case 672:
            mountPatchOffset = 0x33C475;
            // mountPatchOffset2 (check did not exist on 6.72 yet)
            fwCheckPatch = 0x3DB6F8;
            disableCoreDumpPatch = 0x306BCB;
            break;
        case 702:
            mountPatchOffset = 0x31BBBB;
            // mountPatchOffset2 (check did not exist on 7.02 yet)
            fwCheckPatch = 0x3B3B38;
            disableCoreDumpPatch = 0x2E790B;
            break;
        case 900:
            // causes issues
            //mountPatchOffset = 0x3232C8;
            //mountPatchOffset2 = 0x3232C0;
            fwCheckPatch = 0x3C5EA7;
            disableCoreDumpPatch = 0x2EFC1B;
            break;
        case 1100:
            // causes issues
            //mountPatchOffset = 0x3210C6;
            //mountPatchOffset2 = 0x3210BC;
            fwCheckPatch = 0x3C41A7;
            disableCoreDumpPatch = 0x2ECF2B;
            break;
        case 1202:
            fwCheckPatch = 0x3CA567;
            disableCoreDumpPatch = 0x2F126B;
            break;
/* // Missing Offset
        case 1250:
            fwCheckPatch = 0x0;
            disableCoreDumpPatch = 0x0;
            break;
        case 1300:
            fwCheckPatch = 0x0;
            disableCoreDumpPatch = 0x0;
            break;            
*/            
        default:
            break;
    }

    // mount /user on any process sandbox with read/write perm
    uint64_t nop_slide = 0x9090909090909090;
    if (mountPatchOffset) {
        proc_rw_mem(p, (void *)(shellcore_base + mountPatchOffset), 6, &nop_slide, 0, 1);
    }
    if (mountPatchOffset2) {
        proc_rw_mem(p, (void *)(shellcore_base + mountPatchOffset2), 6, &nop_slide, 0, 1);
    }

    // other patches
    if (fwCheckPatch) {
        proc_rw_mem(p, (void *)(shellcore_base + fwCheckPatch), 1, (void *)"\xEB", 0, 1); // always jump
    }
    if (disableCoreDumpPatch) { // thanks to osm
        proc_rw_mem(p, (void *)(shellcore_base + disableCoreDumpPatch), 5, (void *)"\x41\xC6\x45\x0C\x00", 0, 1); // mov byte ptr [r13 + 0x0C], 0
    }

    return 0;
}

void *rwx_alloc(uint64_t size) {
    uint64_t alignedSize = (size + 0x3FFFull) & ~0x3FFFull;
    return (void *)kmem_alloc(*kernel_map, alignedSize);
}

int load_kdebugger() {
    uint64_t mapsize;
    void *kmemory;
    int (*payload_entry)(void *p);

    // calculate mapped size
    if (elf_mapped_size(kernelelf, &mapsize)) {
        printf("[Frame4] invalid kdebugger elf!\n");
        return 1;
    }

    // allocate memory
    kmemory = rwx_alloc(mapsize);
    if (!kmemory) {
        printf("[Frame4] could not allocate memory for kdebugger!\n");
        return 1;
    }

    // load the elf
    if (load_elf(kernelelf, kernelelf_size, kmemory, mapsize, (void **)&payload_entry)) {
        printf("[Frame4] could not load kdebugger elf!\n");
        return 1;
    }

    // call entry
    if (payload_entry(NULL)) {
        return 1;
    }

    return 0;
}

int load_debugger() {
    struct proc *p;
    struct vmspace *vm;
    struct vm_map *map;
    int r;

    p = proc_find_by_name("SceShellCore");
    if (!p) {
        printf("[Frame4] <load_debugger> could not find SceShellCore process!\n");
        return 1;
    }

    printf("[Frame4] <load_debugger> SceShellCore found, pid = %i\n", p->pid);

    vm = p->p_vmspace;
    map = &vm->vm_map;

    // allocate some memory
    vm_map_lock(map);
    r = vm_map_insert(map, NULL, NULL, PAYLOAD_BASE, PAYLOAD_BASE + PAYLOAD_SIZE, VM_PROT_ALL, VM_PROT_ALL, 0);
    vm_map_unlock(map);
    if (r) {
        printf("[Frame4] failed to allocate payload memory, removing previous allocations...\n");
        r = 0;

        vm_map_lock(map);
        r = vm_map_delete(map, PAYLOAD_BASE, PAYLOAD_BASE + PAYLOAD_SIZE);
        vm_map_unlock(map);

        if (r) {
            printf("[Frame4] failed to remove previous allocations, restart your console and try again!\n");
            return r;
        }

        printf("[Frame4] previous allocations removed, reallocating payload memory...\n");
        vm_map_lock(map);
        r = vm_map_insert(map, NULL, NULL, PAYLOAD_BASE, PAYLOAD_BASE + PAYLOAD_SIZE, VM_PROT_ALL, VM_PROT_ALL, 0);
        vm_map_unlock(map);
        if (r) {
            printf("[Frame4] failed to reallocate payload memory, restart your console and try again!\n");
        }
    }

    // write the payload
    r = proc_write_mem(p, (void *)PAYLOAD_BASE, debuggerbin_size, debuggerbin, NULL);
    if (r) {
        printf("[Frame4] failed to write payload!\n");
        return r;
    }

    // create a thread
    r = proc_create_thread(p, PAYLOAD_BASE);
    if (r) {
        printf("[Frame4] failed to create payload thread!\n");
        return r;
    }

    return 0;
}

int runinstaller() {
    init_ksdk();

    // enable uart
    *disable_console_output = 0;

    ascii_art();

    // patch the kernel
    printf("[Frame4] patching kernel...\n");
    patch_kernel();

    printf("[Frame4] loading kdebugger...\n");
    if (load_kdebugger()) {
        return 1;
    }

    printf("[Frame4] loading debugger...\n");
    if (load_debugger()) {
        return 1;
    }

    printf("[Frame4] patching shellcore...\n");
    patch_shellcore();

    printf("[Frame4] Frame4 loaded!\n");

    return 0;
}
