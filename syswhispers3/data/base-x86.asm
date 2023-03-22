		push ebp
		mov ebp, esp
		push #### FUNCTION HASH ADDR ####                        ; Load function hash into ECX.
		#### RANDOM SYSCALL ####
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, #### OFFSET ####
	push_argument_#### FUNCTION HASH ####:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_#### FUNCTION HASH ####
		mov ecx, eax
		#### WOW64 GATE ####
		mov eax, ecx
		push ret_address_epilog_#### FUNCTION HASH ####
		call do_sysenter_interrupt_#### FUNCTION HASH ####
	#### WOW64 FINISH ####
		lea esp, [esp+4]
	ret_address_epilog_#### FUNCTION HASH ####:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_#### FUNCTION HASH ####:
		#### DEBUG ####
		mov edx, esp
		#### SYSCALL ####
