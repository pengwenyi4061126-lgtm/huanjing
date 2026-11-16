; Go 1.25 internal/cpu ABI detours.
;
; cpuid(eaxArg, ecxArg) (eax, ebx, ecx, edx):
;   args at [rsp+8], [rsp+0Ch]
;   results at [rsp+10h], [rsp+14h], [rsp+18h], [rsp+1Ch]
;
; xgetbv() (eax, edx):
;   results at [rsp+8], [rsp+0Ch]

option casemap:none

.code

extern CacGoCpuidFilter:proc
extern CacGoXgetbvFilter:proc

public GoCpuidDetour
public GoXgetbvDetour

GoCpuidDetour proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 30h

    mov     ecx, dword ptr [rbp+10h]
    mov     edx, dword ptr [rbp+14h]
    lea     r8, [rsp+20h]
    call    CacGoCpuidFilter

    mov     eax, dword ptr [rsp+20h]
    mov     dword ptr [rbp+18h], eax
    mov     eax, dword ptr [rsp+24h]
    mov     dword ptr [rbp+1Ch], eax
    mov     eax, dword ptr [rsp+28h]
    mov     dword ptr [rbp+20h], eax
    mov     eax, dword ptr [rsp+2Ch]
    mov     dword ptr [rbp+24h], eax

    mov     rsp, rbp
    pop     rbp
    ret
GoCpuidDetour endp

GoXgetbvDetour proc
    push    rbp
    mov     rbp, rsp
    sub     rsp, 30h

    lea     rcx, [rsp+20h]
    call    CacGoXgetbvFilter

    mov     eax, dword ptr [rsp+20h]
    mov     dword ptr [rbp+10h], eax
    mov     eax, dword ptr [rsp+24h]
    mov     dword ptr [rbp+14h], eax

    mov     rsp, rbp
    pop     rbp
    ret
GoXgetbvDetour endp

end
