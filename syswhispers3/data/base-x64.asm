#### HEADER ####
	mov [rsp +8], rcx                     ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, #### OFFSET ####
	mov ecx, #### FUNCTION HASH ADDR ####                   ; Load function hash into ECX.
	#### RANDOM SYSCALL ####
	call SW3_GetSyscallNumber             ; Resolve function hash into syscall number.
	add rsp, #### OFFSET ####
	mov rcx, [rsp +8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	#### DEBUG ####
	#### SYSCALL ####
#### FOOTER ####
