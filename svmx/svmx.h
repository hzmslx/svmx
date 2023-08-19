#pragma once

#define KVM_DEVICE 0x8000

/*
* ioctls for kvm
*/
/*
* This is identifies the API version as the stable kvm API. It is not
* expected that this number will change. However, Linux 2.6.20 and 
* 2.6.21 report earlier versions; these are not documented and not
* supported. Applications should refuse to run if KVM_GET_API_VERSION
* returns a value other than 12. If this check passes, all ioctls
* described as 'basic' will be available.
*/
#define KVM_GET_API_VERSION				CTL_CODE(KVM_DEVICE,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
/*
* The new VM has no virtual cpus and no memory.
* You probably want to use 0 as machine type.
*/
#define KVM_CREATE_VM					CTL_CODE(KVM_DEVICE,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
/*
* The API allows the application to query about extension to the core
* kvm API. Userspace passes an extension identifier (an integar) and
* receives an integer that describes the extension availability.
* Generally 0 means no and 1 means yes, but some extensions may report
* additional information in the integer return value.
*
* Based on their initialization different VMs may have different capablities.
* It is thus encouraged to use the vm ioctl to query for capabilities
*
* Check if a kvm extension is available.  Argument is extension number,
* return is 1 (yes) or 0 (no, sorry).
*/
#define KVM_CHECK_EXTENSION				CTL_CODE(KVM_DEVICE,0x802,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define KVM_GET_VCPU_MMPA_SIZE			CTL_CODE(KVM_DEVICE,0x803,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define KVM_TRACE_ENABLE				CTL_CODE(KVM_DEVICE,0x804,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define KVM_TRACE_PAUSE					CTL_CODE(KVM_DEVICE,0x805,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define KVM_TRACE_DISABLE				CTL_CODE(KVM_DEVICE,0x806,METHOD_BUFFERED,FILE_ANY_ACCESS)
/*
* KVM_GET_MSR_FEATURE_INDEX_LIST returns the list of MSRs that can be passed
* to the KVM_GET_MSRS system ioctl. This lets userspace probe host capabilities
* and processor features that are exposed via MSRs (e.g., VMX capabilities).
* This list also varies by kvm version and host processor, but does not change
* otherwise.
*/
#define KVM_GET_MSR_FEATURE_INDEX_LIST	CTL_CODE(KVM_DEVICE,0x807,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define KVM_SET_USER_MEMORY_REGION		CTL_CODE(KVM_DEVICE,0x808,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* ioctls for vcpu
*/
/*
* This API adds a vcpu to a virtual machine. No more than max_vcpus may be added.
* The vcpu id is an integer in the range [0,max_cpu_id).
* 
* The recommeded max_vcpus value can be retrieved using the KVM_CAP_NR_VCPUS of
* the KVM_CHECK_EXTENSION ioctl() at run-time.
* The maximum possible value for max_vcpus can be retrieved using the 
* KVM_CAP_MAX_VCPUS of the KVM_CHECK_EXTENSION ioctl() at run-time.
* 
* If the KVM_CAP_NR_VCPUS does not exist, you should assume that max_vcpus is 4
* cpus max.
* If the KVM_CAP_MAX_VCPUS does not exist, you should assume that max_vcpus is 
* same as the value returned from KVM_CAP_NR_VCPUS.
* 
* The maximum possible value for max_vcpu_id can be retrieved using the
* KVM_CAP_MAX_VCPU_ID of the KVM_CHECK_EXTENSION ioctl() at run time
* 
* If the KVM_CAP_MAX_VPU_ID doesn't exist, you should assume that max_vcpu_id
* is the same as the value returned from KVM_CAP_MAX_VCPUS.
*/
#define KVM_CREATE_VCPU		CTL_CODE(KVM_DEVICE,0x809,METHOD_BUFFERED,FILE_ANY_ACCESS)
/*
* This ioctl is used to run a guest virtual cpu. While there are no
* explicit parameters, there is an implicit parameter block that can
* be obtained by mmap()ing the vcpu fd at offset 0, with the size given by
* KVM_GET_VCPU_MMAP_SIZE. The parameter block is formatted as a 'struct
* kvm_run'
*/
#define KVM_RUN				CTL_CODE(KVM_DEVICE,0x80A,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define KVM_SET_SREGS2		CTL_CODE(KVM_DEVICE,0x80B,METHOD_BUFFERED,FILE_ANY_ACCESS)


/*
*
*
*  struct kvm_msr_list {
*	__u32 nmsrs; // number of msrs in entries
*	__u32 indices[0];
*  };
*
* The user fills in the size of the indices array in msrs, and in return
* kvm adjusts nmsrs to reflect the actual number of msrs and fills in the
* indices array with their numbers.
* 
* KVM_GET_MSR_INDEX_LIST returns the guest msrs that are supported. The list
* varies by kvm version and host processor, but doesn't not change otherwise.
* 
* Note: if kvm indicates supports MCE (KVM_CAP_MCE), then the MCE back MSRs are
* not returned in the MSR list, as different vcpus can have a different number
* of banks, as set via the KVM_X86_SETUP_MCE ioctl.
*/
#define KVM_GET_MSR_INDEX_LIST	CTL_CODE(KVM_DEVICE,0x80D,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* When used as a system ioctl:
* Reads the values of MSR-based features that are available for the VM. This
* is similar to KVM_GET_SUPPORTED_CPUID, but it returns MSR indices and values.
* The list of msr-based features can be obtained using KVM_GET_MSR_FEATURE_INDEX_LIST
* in a system ioctl.
* 
* When used as a vcpu ioctl:
* Reads model-specific registers from the vcpu. Supported msr indices can be obtained
* using KVM_GET_MSR_INDEX_LIST in a system ioctl.
* 
* Application code should set the 'nmsrs' member (which indicates the 
* size of the entries array) and the 'index' member of each array entry.
* kvm will fill in the 'data' member.
*/
#define KVM_GET_MSRS	CTL_CODE(KVM_DEVICE,0x80E,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* The KVM_RUN ioctl (cf.) communicates with userspace via a shared 
* memory region. This ioctl returns the size of that region. See the
* KVM_RUN documentation for details.
* 
* Besides the size of the KVM_RUN communication region, other areas of 
* the VCPU file descriptor can be mmaped, including:
* 
* - if KVM_CAP_COALESCED_MMIO is available, a page at
* KVM_COALESCED_MMIO_PAGE_OFFSET * PAGE_SIZE; for historical reasons,
* this page is included in the result of KVM_GET_VCPU_MMAP_SIZE.
* KVM_CAP_COALESCED_MMIO is not documented yet.
* 
* - if KVM_CAP_DIRTY_LOG_RING is available, a number of pages at 
* KVM_DIRTY_LOG_PAGE_OFFSET * PAGE_SIZE.
*/
#define KVM_GET_VCPU_MMAP_SIZE CTL_CODE(KVM_DEVICE,0x80F,METHOD_BUFFERED,FILE_ANY_ACCESS)


/*
* Given a memory slot, return a bitmap containing any pages dirtied
* since the last call to this ioctl. Bit 0 is the first page in the
* memory slot. Ensure the entire structure is cleared to avoid padding
* issues.
* 
* If KVM_CAP_MULTI_ADDRESS_SPACE is vailable, bits 16-31 of slot field specifies
* the address space for which you want to return the dirty bitmap. See
* KVM_SET_USER_MEMORY_REGION for details on the usage of slot field.
* 
* The bits in the dirty bitmap are cleared before the ioctl returns, unless
* KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2 is enabled. For more information,
* see the description of the capability.
* 
*/
#define KVM_GET_DIRTY_LOG CTL_CODE(KVM_DEVICE,0x810,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Reads the general purpose registers from the vcpu.
*/
#define KVM_GET_REGS CTL_CODE(KVM_DEVICE,0x811,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Writes the general purpose registers into the vcpu.
*/
#define KVM_SET_REGS CTL_CODE(KVM_DEVICE,0x812,METHOD_BUFFERED,FILE_ANY_ACCESS)
/*
* Read special registers from the vcpu.
* 
* interrupt_bitmap is a bitmap of pending external interrupts. At most
* one bit may be set. This interrupt has been acknowleded by the APIC
* but not yet injected into the cpu core.
*/
#define KVM_GET_SREGS CTL_CODE(KVM_DEVICE,0x813,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Writes special registers into the vcpu.
*/
#define KVM_SET_SREGS CTL_CODE(KVM_DEVICE,0x814,METHOD_BUFFERED,FILA_ANY_ACCESS)

/*
* Translates a virtual address according to the vcpu's current address
* translation mode.
*/
#define KVM_TRANSLATE CTL_CODE(KVM_DEVICE,0x815,METHOD_BUFFERED,FILA_ANY_ACCESS)


/*
* Queues a hardware interrupt vector to be injected.
*/
#define KVM_INTERRUPT CTL_CODE(KVM_INTERRUPT,0x816,METHOD_BUFFERED,FILA_ANY_ACCESS)

/*
* Writes model-specific registers to the vcpu. 
* 
* Application code should set the 'nmsrs' member (which indicates the
* size of the entries array),and the 'index' and 'data' members of each
* array entry.
* 
* It tries to set the MSRs in array entries[] one by one. If setting an MSR
* fails, e.g., due to setting reserved bits, the MSR isn't supported/emulated
* by KVM, etc..., it stops prossing the MSR list and returns the number of 
* MSRs that have been set successfully.
*/
#define KVM_SET_MSRS CTL_CODE(KVM_INTERRUPT,0x817,METHOD_BUFFERED,FILA_ANY_ACCESS)

/*
* Defines the vcpu responses to the cpuid instruction. Applications
* should use the KVM_SET_CPUID2 ioctl if avaiable.
* 
* Caveat emptor:
*	- If this IOCTL fails, KVM gives no guarantees that previous valid CPUID
*	  configuration (if there is) is not corrupted. Userspace can get a copy
*	  of the resulting CPUID configuration through KVM_GET_CPUID2 in case.
*	- Using KVM_SET_CPUID{,2} after KVM_RUN, i.e. changing the guest vCPU model
*	  after running the guest, may be cause guest instability.
*	- Using heterogeneous CPUID configurations, modulo APIC IDs, topology, etc...
*	  may cause guest instability.
* 
* 
*/
#define KVM_SET_CPUID CTL_CODE(KVM_INTERRUPT,0x818,METHOD_BUFFERED,FILA_ANY_ACCESS)

/*
* Reads the floating point state from the vcpu.
*/
#define KVM_GET_FPU CTL_CODE(KVM_INTERRUPT,0x819,METHOD_BUFFERED,FILA_ANY_ACCESS)

/*
* Writes the floating point state to the vcpu.
*/
#define KVM_SET_FPU CTL_CODE(KVM_INTERRUPT,0x81A,METHOD_BUFFERED,FILA_ANY_ACCESS)

/*
* Creates an interrupt controller model in the kernel.
* On x86, creates a virtual ioapic, a virtual PIC (two PICs, nested), and sets up
* futrue vcpus to have a local APIC. IRQ routing for GSIs 0-15 is set to both
* PIC and IOAPIC; GSI 16-23 only go to the IOAPIC.
*/
#define KVM_CREATE_IRQCHIP CTL_CODE(KVM_INTERRUPT,0x81B,METHOD_BUFFERED,FILA_ANY_ACCESS)

/*
* Set the level of a GSI input to the interrupt controller model in the kernel.
* On some architectures it is required that an interrupt controller model has
* been previously created with KVM_CREATE_IRQCHIP. Note that edge-triggered
* interrupts require the level to be set to 1 and then back to 0.
* 
* On real hardware, interrupt pins can be active-low or active-high, This
* does not matter for the level field of struct kvm_irq_level:1 always
* means active (asserted), 0 means inactive (deasserted).
* 
* x86 allows the operating system to program the interrupt polarity
* (active-low/active high) for level-triggered interrupts, and KVM used
* to consider the polarity. However, due to bitrot in the handling of
* active-low interrupts, the above convention is now valid on x86 too.
* This is signaled  by KVM_CAP_X86_IOAPIC_POLARITY_IGNORED. Userspace
* should not present interrupts to the guest as active-low unless this 
* capability is present (or unless it is not using the in-kernel irqchip,
* of course).
* 
* 
*/
#define KVM_IRQ_LINE CTL_CODE(KVM_INTERRUPT,0x81C,METHOD_BUFFERED,FILA_ANY_ACCESS)

/*
* Reads the state of a kernel interrupt controller created with
* KVM_CREATE_IRQCHIP into a buffer provided by the caller.
*/
#define KVM_GET_IRQCHIP CTL_CODE(KVM_INTERRUPT,0x81D,METHOD_BUFFERED,FILA_ANY_ACCESS)

/*
* Sets the state of a kernel interrupt controller created with 
* KVM_CREATE_IRQCHIP from a buffer provided by the caller.
*/
#define KVM_SET_IRQCHIP CTL_CODE(KVM_INTERRUPT,0x81E,METHOD_BUFFERED,FILA_ANY_ACCESS)

/*
* Gets the current timestamp of kvmclock as seen by the current guest. In 
* conjunction with KVM_SET_CLOCK, it is used to ensure monotonicity on scenarios
* such as migration.
*/
#define KVM_GET_CLOCK CTL_CODE(KVM_INTERRUPT,0x81F,METHOD_BUFFERED,FILA_ANY_ACCESS)

/*
* Sets the current timestamp of kvmclock to the value specified in its parameter.
* In conjunction with KVM_GET_CLOCK, it is used to ensure monotonicity on scenarios
* such as migration.
*/
#define KVM_SET_CLOCK CTL_CODE(KVM_INTERRUPT,0x820,METHOD_BUFFERED,FILA_ANY_ACCESS)

/*
* Gets currently pending exceptions, interrupts, and NMIs as well as related
* states of the vcpu.
*/
#define KVM_GET_VCPU_EVENTS CTL_CODE(KVM_INTERRUPT,0x821,METHOD_BUFFERED,FILA_ANY_ACCESS)

