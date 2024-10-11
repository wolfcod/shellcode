
PUBLIC _memset

; rcx = _Dst
; rdx = _Size
_memset PROC
	push rdi
	xor rax, rax
	mov	rdi, rcx
	mov	rcx, rdx
	rep stosb
	pop rdi
	ret
_memset ENDP