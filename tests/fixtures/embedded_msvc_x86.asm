.686
.XMM
.MODEL flat, c
ASSUME fs:_DATA
.code

EXTERN SW3_GetSyscallNumber: PROC
EXTERN local_is_wow64: PROC

NtAccessCheck PROC
		push ebp
		mov ebp, esp
		push 0009F8486h                        ; Load function hash into ECX.
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_009F8486:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_009F8486
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_009F8486
		call do_sysenter_interrupt_009F8486
		lea esp, [esp+4]
	ret_address_epilog_009F8486:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_009F8486:
		mov edx, esp
		sysenter
		ret
NtAccessCheck ENDP

end