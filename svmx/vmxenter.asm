PUBLIC vmx_get_cs

.data

EXTERN vmx_update_host_rsp :PROC
EXTERN vmx_spec_ctrl_restore_host :PROC

VMX_RUN_VMRESUME DD 1
VCPU_RAX	DQ	0
VCPU_RCX	DQ	0
VCPU_RDX	DQ	0
VCPU_RBX	DQ	0
VCPU_RBP	DQ	0
VCPU_RSI	DQ	0
VCPU_RDI	DQ	0
VCPU_R8		DQ	0
VCPU_R9		DQ	0
VCPU_R10	DQ	0
VCPU_R11	DQ	0
VCPU_R12	DQ	0
VCPU_R13	DQ	0
VCPU_R14	DQ	0
VCPU_R15	DQ	0

.code



;__vmx_vcpu_run - Run a vCPU via a transition to VMX guest mode
; @vmx:	struct vcpu_vmx *
; @regs:	unsigned long * (to guest registers)
; @flags:	VMX_RUN_VMRESUME:	use VMRESUME instead of VMLAUNCH
;		VMX_RUN_SAVE_SPEC_CTRL: save guest SPEC_CTRL into vmx->spec_ctrl
;
;Returns:
;	0 on VM-Exit, 1 on VM-Fail
;
__vmx_vcpu_run PROC
	push rbp
	mov	 rsp,rbp
	push r15
	push r14
	push r13
	push r12
	push rdi
	push rsi
	push rbx

	; Save @vmx for SPEC_CTRL handling
	push rcx
	
	; Save @flags for SPEC_CTRL handling
	push r8

	;
	; Save @regs, regs may be modified by vmx_update_host_rsp() and
	; @regs is needed after VM-Exit to save the guest's register values.
	;
	push rdx

	; Copy @flags to rbx, r8 is volatile.
	mov rbx,r8

	lea rdx,[rsp]
	call vmx_update_host_rsp

	jmp Lspec_ctrl_done

Lspec_ctrl_done:
	;
	; Since vmentry is serializing on affected CPUs, there's no need for
	; an LFENCE to stop speculation from skipping the wrmsr.
	;

	; Load @regs to RAX.
	mov rax,[rsp]

	; Check if vmlaunch or vmresume is needed.
	test VMX_RUN_VMRESUME,ebx

	; Load guest registers, Don't clobber flags
	mov VCPU_RCX,rcx
	mov VCPU_RDX,rdx
	mov VCPU_RBX,rbx
	mov VCPU_RBP,rbp
	mov VCPU_RSI,rsi
	mov VCPU_RDI,rdi
	mov VCPU_R8,r8
	mov VCPU_R9,r9
	mov VCPU_R10,r10
	mov VCPU_R11,r11
	mov VCPU_R12,r12
	mov VCPU_R13,r13
	mov VCPU_R14,r14
	mov VCPU_R15,r15
	
	; Load guest RAX, This kills the @regs pointer! 
	mov VCPU_RAX,RAX
	jz Lvmlaunch

	;
	; After a successful VMRESUME/VMLAUNCH, control flow "magically"
	; resumes below at 'vmx_vmexit' due to the VMCS HOST_RIP setting.
	; So this isn't a typical function and objtool needs to be told to
	; save the unwind state here and restore it below.


Lvmlaunch:
	vmlaunch


__vmx_vcpu_run ENDP

vmx_get_es PROC
	mov ax,fs
	ret
vmx_get_es ENDP


vmx_get_cs PROC
	mov ax,cs
	ret
vmx_get_cs ENDP

vmx_get_ss PROC
	mov ax,ss
	ret
vmx_get_ss ENDP

vmx_get_ds PROC
	mov ax,ds
	ret
vmx_get_ds ENDP

vmx_get_fs PROC
	mov ax,fs
	ret
vmx_get_fs ENDP

vmx_get_gs PROC
	mov ax,gs
	ret
vmx_get_gs ENDP

vmx_sgdt PROC
	sgdt fword ptr [rcx]
	ret
vmx_sgdt ENDP

vmx_str PROC
	str ax
	ret
vmx_str ENDP

vmx_sldt PROC
	sldt ax
	ret
vmx_sldt ENDP

vmx_vmexit PROC

	; Temporarily save guest's RAX.
	push rax

	; Reload @regs to RAX.
	mov rax,[rsp]

	; Save all guest registers, including RAX from the stack
	pop VCPU_RAX
	mov VCPU_RCX,rcx
	mov VCPU_RDX,rdx
	mov VCPU_RBX,rbx
	mov VCPU_RBP,rbp
	mov VCPU_RSI,rsi
	mov VCPU_RDI,rdi
	mov VCPU_R8,r8
	mov VCPU_R9,r9
	mov VCPU_R10,r10
	mov VCPU_R11,r11
	mov VCPU_R12,r12
	mov VCPU_R13,r13
	mov VCPU_R14,r14
	mov VCPU_R15,r15

	; Clear return value to indicate VM-Exit (as opposed to VM-Fail).
	xor ebx,ebx

	; Discard @regs. The register is irrelevant, it just can't be RBX.
	pop rax

	;
	; Clear all general purpose register except RSP and RBX to prevent
	; speculative use of the guest's values, even those that are reloadoed
	; via the stack. In theory, an L1 cache miss when restoring registers
	; could lead to speculative execution with the guest's values.
	; Zeroing XORs are dirt cheap, i.e. the extra paranoia is essentially
	; free. RSP and RBX are exempt as RSP is restored by hardware during
	; VM-Exit and RBX is explicitly loaded with 0 or 1 to hold the return
	; value.
	;
	xor eax,eax
	xor ecx,ecx
	xor edx,edx
	xor ebp,ebp
	xor esi,esi
	xor edi,edi
	xor r8d,r8d
	xor r9d,r9d
	xor r10d,r10d
	xor r11d,r11d
	xor r12d,r12d
	xor r13d,r13d
	xor r14d,r14d
	xor r15d,r15d

	;
	; IMPORTANT: RSB filling and SPEC_CTRL handling must be done before
	; the first unbalanced RET after vmexit!
	;
	; For retpoline or IBRS, RSB filling is needed to prevent poisoned RSB
	; entries and (in some cases) RSB underflow.
	;
	; eIBRS has its own protection against poisoned RSB, so it doesn't
	; need the RSB filling sequence.  But it does need to be enabled, and a
	; single call to retire, before the first unbalanced RET.
	;

	pop rdx
	pop rcx

	call vmx_spec_ctrl_restore_host

	; Put return value in AX
	mov rax,rbx

	pop rbx

	pop r12
	pop r13
	pop r14
	pop r15
	pop rbp
	ret
vmx_vmexit ENDP










END

