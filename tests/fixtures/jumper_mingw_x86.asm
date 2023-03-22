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
		push 0xCC97DD3D                        ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset
		mov edi, eax                          ; Save the address of the syscall
		push 0xCC97DD3D                     ; Re-Load function hash into ECX (optional)
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0x5
	push_argument_CC97DD3D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_CC97DD3D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_CC97DD3D
		call do_sysenter_interrupt_CC97DD3D
		lea esp, [esp+4]
	ret_address_epilog_CC97DD3D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_CC97DD3D:
		mov edx, esp
		jmp edi                            ; Jump to -> Invoke system call.
		ret
NtAccessCheck ENDP

end