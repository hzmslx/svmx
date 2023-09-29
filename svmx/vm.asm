.data

EXTERN kvm_arch_vcpu_ioctl_run :PROC
EXTERN guest_stack_pointer :DQ

.code

ALIGN 16		; Specify function alignment
vm_save_state PROC
	sub rsp,8h
	mov guest_stack_pointer,rsp
	call kvm_arch_vcpu_ioctl_run
	mov rax,0C0000001h
	add rsp,8h
	ret
vm_save_state ENDP

ALIGN 16		; Specify function alignment
vm_restore_state PROC
	nop
	add rsp,8h
	ret
vm_restore_state ENDP

END