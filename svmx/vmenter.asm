PUBLIC vmx_get_cs

.data

EXTERN vmx_update_host_rsp :PROC

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

END

