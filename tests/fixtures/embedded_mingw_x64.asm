.code

EXTERN SW3_GetSyscallNumber: PROC


NtAccessCheck PROC
	mov [rsp +8], rcx                     ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 0x28
	mov ecx, 0x009C0B3D                   ; Load function hash into ECX.
	call SW3_GetSyscallNumber             ; Resolve function hash into syscall number.
	add rsp, 0x28
	mov rcx, [rsp +8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall
	ret
NtAccessCheck ENDP

end