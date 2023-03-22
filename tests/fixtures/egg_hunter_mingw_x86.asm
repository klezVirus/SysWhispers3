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
		push 0x0922DE0E                        ; Load function hash into ECX.
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0x5
	push_argument_0922DE0E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0922DE0E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0922DE0E
		call do_sysenter_interrupt_0922DE0E
		lea esp, [esp+4]
	ret_address_epilog_0922DE0E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0922DE0E:
		mov edx, esp
		db 0x65,0x0,0x0,0x6e,0x65,0x0,0x0,0x6e
		ret
NtAccessCheck ENDP

end