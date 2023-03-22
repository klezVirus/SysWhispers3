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
		push 008A61A1Fh                        ; Load function hash into ECX.
		call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.
		mov edi, eax                          ; Save the address of the syscall
		push 008A61A1Fh                     ; Re-Load function hash into ECX (optional)
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_08A61A1F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_08A61A1F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_08A61A1F
		call do_sysenter_interrupt_08A61A1F
		lea esp, [esp+4]
	ret_address_epilog_08A61A1F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_08A61A1F:
		mov edx, esp
		jmp edi                            ; Jump to -> Invoke system call.
		ret
NtAccessCheck ENDP

end