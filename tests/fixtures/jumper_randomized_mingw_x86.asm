.686
.XMM
.MODEL flat, c
ASSUME fs:_DATA
.code

EXTERN SW3_GetSyscallNumber: PROC
EXTERN local_is_wow64: PROC
EXTERN SW3_GetRandomSyscallAddress: PROC


NtAccessCheck PROC
		push ebp
		mov ebp, esp
		push 0x1CA2032B                        ; Load function hash into ECX.
		call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
		mov edi, eax                          ; Save the address of the syscall
		push 0x1CA2032B                     ; Re-Load function hash into ECX (optional)
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0x5
	push_argument_1CA2032B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1CA2032B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1CA2032B
		call do_sysenter_interrupt_1CA2032B
		lea esp, [esp+4]
	ret_address_epilog_1CA2032B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1CA2032B:
		mov edx, esp
		jmp edi                            ; Jump to -> Invoke system call.
		ret
NtAccessCheck ENDP

end