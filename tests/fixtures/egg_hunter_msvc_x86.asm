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
		push 009A2100Fh                        ; Load function hash into ECX.
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_09A2100F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_09A2100F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_09A2100F
		call do_sysenter_interrupt_09A2100F
		lea esp, [esp+4]
	ret_address_epilog_09A2100F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_09A2100F:
		mov edx, esp
		db 68h,0h,0h,69h,68h,0h,0h,69h
		ret
NtAccessCheck ENDP

end