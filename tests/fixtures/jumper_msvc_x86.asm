.686
.XMM
.MODEL flat, c
ASSUME fs:_DATA
.code

EXTERN SW3_GetSyscallNumber: PROC
EXTERN local_is_wow64: PROC
EXTERN SW3_GetSyscallAddress: PROC


NtAccessCheck PROC
		push ebp
		mov ebp, esp
		push 0B6956ED5h                        ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset
		mov edi, eax                          ; Save the address of the syscall
		push 0B6956ED5h                     ; Re-Load function hash into ECX (optional)
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_B6956ED5:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_B6956ED5
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_B6956ED5
		call do_sysenter_interrupt_B6956ED5
		lea esp, [esp+4]
	ret_address_epilog_B6956ED5:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_B6956ED5:
		mov edx, esp
		jmp edi                            ; Jump to -> Invoke system call.
		ret
NtAccessCheck ENDP

end