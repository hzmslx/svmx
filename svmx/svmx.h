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

/*
* This ioctl allows the user to create, modify or delete a guest physical
* memory slot. Bits 0-15 of "slot" specify the slot id and this value
* should be less than the maximum number of user memory slots supported per
* VM. The maximum allowed slots can be queried  using KVM_CAP_NR_MEMSLOTS.
* Slots may not overlap in guest physical address space.
* 
* If KVM_CAP_MULTI_ADDRESS_SPACE is available, bits 16-31 of "slot"
* specifies the address space which is being modified. They must be
* less than the value that KVM_CHECK_EXTENSION returns for the 
* KVM_CAP_MULTI_ADDRESS_SPACE capability. Slots in separate address spaces
* are unrelated; the restriction on overlapping slots only applies within
* each address space.
* 
* Deleting a slot is done by passing zero for memory_size. When changing
* an existing slot, it may be moved in the guest physical memory space,
* or its flags may be modified, but it may not be resized.
* 
* Memory for the region is taken starting at the address denoted by the 
* field userpsace_addr, which must point at user addressable memory for the
* entire memory slot size. Any object may back this memory, including 
* annoymous memory, ordinary files, and hugetlbfs.
* 
* On architetures that support a form of address tagging, userspace_addr must
* be an untagged address.
* 
* It is recommended that the lower 21 bits of guest_phys_addr and userspace_addr
* be identical. This allows large pages in the guest to backed by large
* pages in the host.
* 
* The flags field supports two flags: KVM_MEM_LOG_DIRTY_PAGES and 
* KVM_MEM_READONLY. The former can be set to instruct KVM to keep track of
* write to memory within the slot. See KVM_GET_DIRTY_LOG ioctl to know how to
* use it. The latter can be set, if KVM_CAP_READONLY_MEM capability allows it,
* to make a new slot read-only. In this case, writes to this memory will be
* posted to userspace as KVM_EXIT_MMIO exits.
* 
* When the KVM_CAP_SYNC_MMU capability is available, changes in the backing of the
* memory region are automatically reflected into the guest. For example, an 
* mmap() that affects the region will be amde visible immediately. Another
* example is madvise(MADV_DROP).
*
*/
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

/*
* Writes special registers into the vcpu.
* This ioctl (when supported) replaces the KVM_SET_SREGS.
*/
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
* Translates a virtual address according to the vcpu's current address
* translation mode.
*/
#define KVM_TRANSLATE CTL_CODE(KVM_DEVICE,0x815,METHOD_BUFFERED,FILE_ANY_ACCESS)


/*
* Queues a hardware interrupt vector to be injected.
*/
#define KVM_INTERRUPT CTL_CODE(KVM_DEVICE,0x816,METHOD_BUFFERED,FILE_ANY_ACCESS)

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
#define KVM_SET_MSRS CTL_CODE(KVM_DEVICE,0x817,METHOD_BUFFERED,FILE_ANY_ACCESS)

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
#define KVM_SET_CPUID CTL_CODE(KVM_DEVICE,0x818,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Reads the floating point state from the vcpu.
*/
#define KVM_GET_FPU CTL_CODE(KVM_DEVICE,0x819,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Writes the floating point state to the vcpu.
*/
#define KVM_SET_FPU CTL_CODE(KVM_DEVICE,0x81A,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Creates an interrupt controller model in the kernel.
* On x86, creates a virtual ioapic, a virtual PIC (two PICs, nested), and sets up
* futrue vcpus to have a local APIC. IRQ routing for GSIs 0-15 is set to both
* PIC and IOAPIC; GSI 16-23 only go to the IOAPIC.
*/
#define KVM_CREATE_IRQCHIP CTL_CODE(KVM_DEVICE,0x81B,METHOD_BUFFERED,FILE_ANY_ACCESS)

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
#define KVM_IRQ_LINE CTL_CODE(KVM_DEVICE,0x81C,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Reads the state of a kernel interrupt controller created with
* KVM_CREATE_IRQCHIP into a buffer provided by the caller.
*/
#define KVM_GET_IRQCHIP CTL_CODE(KVM_DEVICE,0x81D,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Sets the state of a kernel interrupt controller created with 
* KVM_CREATE_IRQCHIP from a buffer provided by the caller.
*/
#define KVM_SET_IRQCHIP CTL_CODE(KVM_DEVICE,0x81E,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Gets the current timestamp of kvmclock as seen by the current guest. In 
* conjunction with KVM_SET_CLOCK, it is used to ensure monotonicity on scenarios
* such as migration.
*/
#define KVM_GET_CLOCK CTL_CODE(KVM_DEVICE,0x81F,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Sets the current timestamp of kvmclock to the value specified in its parameter.
* In conjunction with KVM_GET_CLOCK, it is used to ensure monotonicity on scenarios
* such as migration.
*/
#define KVM_SET_CLOCK CTL_CODE(KVM_DEVICE,0x820,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Gets currently pending exceptions, interrupts, and NMIs as well as related
* states of the vcpu.
*/
#define KVM_GET_VCPU_EVENTS CTL_CODE(KVM_DEVICE,0x821,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Set pending exceptions, interrupts, and NMIs as well as related states of the
* vcpu.
*/
#define KVM_SET_VCPU_EVENTS CTL_CODE(KVM_DEVICE,0x822,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Reads debug registers from the vcpu.
*/
#define KVM_GET_DEBUGREGS CTL_CODE(KVM_DEVICE,0x823,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Writes debug registers into the vcpu.
*/
#define KVM_SET_DEBUGREGS CTL_CODE(KVM_DEVICE,0x824,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* This ioctl defines the phsical address of a three-page region in the guest
* physical address space. The region must be within the first 4GB of the
* guest physical address space and must not conflict with any memory slot
* or any mmio address. The guest may malfunction if it accesses this memory
* region.
* 
* This ioctl is required on Intel-based hosts. This is needed on Intel hardware
* because of a quirk in the virtualization implementation (see the internals
* documentation when it pops into existence).
*/
#define KVM_SET_TSS_ADDR CTL_CODE(KVM_DEVICE,0x825,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Not all extension are enabled by default. Using this ioctl the application
* can enable an extension, making it available to the guest.
* 
* On systems that do not support this ioctl, it always fails. On systems that
* do support it, it only works for extensions that are supported for enablement.
* 
* To check if a capability can be enabled, the KVM_CHECK_EXTENSION ioctl should
* be used.
*/
#define KVM_ENABLE_CAP CTL_CODE(KVM_DEVICE,0x826,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Returns the vcpu's current "multiprocessing state" (though also valid on
* uniprocessor guests).
* 
* On x86, this ioctl is only useful after KVM_CREATE_IRQCHIP. Without an 
* in-kernel irqchip, the multiprocessing state must be maintained by userspace on
* these architectures.
*/
#define KVM_GET_MP_STATE CTL_CODE(KVM_DEVICE,0x827,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Define which vcpu is the Boostrap Processor (BSP). Values are the same as 
* the vcpu id in KVM_CREATE_VCPU. If this ioctl is not called, the default
* is vcpu 0. This ioctl has to be called before vcpu creation,
* otherwise it will return error.
*/
#define KVM_SET_BOOT_CPU_ID CTL_CODE(KVM_DEVICE,0x828,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* This ioctl would copy current vcpu's xsave struct to the userspace.
*/
#define KVM_GET_XSAVE CTL_CODE(KVM_DEVICE,0x829,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* This ioctl would copy userspace's xsave struct to the kernel. It copies
* as many bytes as are returned by KVM_CHECK_EXTENSION(KVM_CAP_XSAVE2),
* KVM_CHECK_EXTENSION(KVM_CAP_XSAVE2) will always be at least 4096.
* Currently, it is only greater than 4096 if a dynamic feature has been
* enabled with ``arch_prctl()``, but this may change in the future.
* 
* The offsets of the state save areas in struct kvm_xsave follow the
* contents of CPUID leaf 0xD on the host.
*/
#define KVM_SET_XSAVE CTL_CODE(KVM_DEVICE,0x82A,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* This ioctl would copy current vcpu's xcrs to the userspace.
*/
#define KVM_GET_XCRS CTL_CODE(KVM_DEVICE,0x82B,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* This ioctl would set vcpu's xcr to the value userspace specified.
*/
#define KVM_SET_XCRS CTL_CODE(KVM_DEVICE,0x82C,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* This ioctl returns x86 cpuid features which are supported by both the 
* hardware and kvm in its default configuration. Userspace can use the 
* information returned by this ioctl to construct cpuid information (for
* KVM_SET_CPUID2) that is consistent with hardware, kernel, and 
* userspace capabilties, and with user requirements (for example, the 
* user may wish to constrain cpuid to emulate older hardware, or for 
* feature consistency across a cluster).
*
*/
#define KVM_GET_SUPPORTED_CPUID CTL_CODE(KVM_DEVICE,0x82D,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* This ioctl fetches PV specific information that need to pe passed to the guest
* using the device or other means from vm context.
* 
* The hcall array defines 4 instructions that make up a hypercall.
* 
* If any additional field gets added to this structure later on, a bit for that
* additional piece of information will be set in the flags bitmap.
*/
#define KVM_PPC_GET_PVINFO CTL_CODE(KVM_DEVICE,0x82E,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Sets the GSI routing table entries, overwriting any previously set entries.
*/
#define KVM_SET_GSI_ROUTING CTL_CODE(KVM_DEVICE,0x82F,METHOD_BUFFERED,FILE_ANY_ACCESS)


/*
* Sepecifies  the tsc frequency for the virtual machine. The unit of the
* frequency is KHz.
*/
#define KVM_SET_TSC_KHZ CTL_CODE(KVM_DEVICE,0x830,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Returns the tsc frequency of the guest. The unit of the return value is
* KHz. 
*/
#define KVM_GET_TSC_KHZ CTL_CODE(KVM_DEVICE,0x830,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Reads the Local APIC registers and copies them into the input argument. The
* data format and layout are the same as documented in the architecture manual.
*/
#define KVM_GET_LAPIC CTL_CODE(KVM_DEVICE,0x831,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Copies the input argument into the Local APIC registers. The data format 
* and layout are the same as documented in the architecture manual.
*/
#define KVM_SET_LAPIC CTL_CODE(KVM_DEVICE,0x832,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* This must be called whenever userspace has changed an entry in the shared
* TLB, prior to calling KVM_RUN on the associated vcpu.
*/
#define KVM_DIRTY_TLB CTL_CODE(KVM_DEVICE,0x833,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Queues an NMI on the thread's vcpu. Note this is well defined only
* when KVM_CREATE_IRQCHIP has not been called, since this is an interface
* between the virtual cpu core and virtual local APIC. After KVM_CREATE_IRQCHIP
* has been called, this interface is completely emulated within the kernel.
*/
#define KVM_NMI CTL_CODE(KVM_DEVICE,0x834,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* This ioctl sets a flag accessible to the guest indicating that the specified
* vCPU has been paused by the host userspace.
*/
#define KVM_KVMCLOCK_CTRL CTL_CODE(KVM_DEVICE,0x835,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Directly inject a MSI message. Only valid with in-kernel irqchip that handles
* MSI messages.
*/
#define KVM_SIGNAL_MSI CTL_CODE(KVM_DEVICE,0x836,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Creates an in-kernel device model for the i8254 PIT. This call is only valid
* after enabling in-kernel irqchip support via KVM_CREATE_IRQCHIP. The following
* parameters have to be passed.
*/
#define KVM_CREATE_PIT2 CTL_CODE(KVM_DEVICE,0x837,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Retrieves the state of the in-kernel PIT model. Only valid after
* KVM_CREATE_PIT2. 
*/
#define KVM_GET_PIT2 CTL_CODE(KVM_DEVICE,0x838,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Sets the state of the in-kernel PIT model. Only valid after KVM_CREATE_PIT2.
* See KVM_GET_PIT2 for details on struct kvm_pit_state2.
* 
* This IOCTL replaces the obsolete KVM_SET_PIT.
*/
#define KVM_SET_PIT2 CTL_CODE(KVM_DEVICE,0x839,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* The member 'flag' is used for passing flags from userspace.
* 
* This ioctl returns x86 cpuid features which are emulated by 
* kvm.Userspace can use the information returned by this ioctl to query
* which features are emulated by kvm instead of bing present natively.
* 
* 
*/
#define KVM_GET_EMULATED_CPUID CTL_CODE(KVM_DEVICE,0x83A,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Queues an SMI on the thread's vcpu.
*/
#define KVM_SMI CTL_CODE(KVM_DEVICE,0x83B,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* This ioctl allows userspace to define up to 16 bitmaps of MSR ranges to deny
* guest MSR accesses that would normally be allowed by KVM. If an MSR is not
* covered by a specific range, the "default" filtering behavior applies. Each
* bitmap range covers MSRs from [base .. base+nmsrs).
* 
* If an MSR access is denied by userspace, the resulting KVM behavior depends on
* whether or not KVM_CAP_X86_USER_SPACE_MSR's KVM_MSR_EXIT_REASON_FILTER is
* enabled. If KVM_MSR_EXIT_REASON_FILTER is enabled, KVM will exit to userspace
* on denied accesses, i.e. userspace effectively intercepts the MSR access. If
* KVM_MSR_EXIT_REASON_FAILTER is not enabled, KVM will inject a #GP into the guest
* on denied accesses.
* 
* If an MSR access is allowed by userspace, KVM will emulate and/or vairtualize
* the access in accordance with the vCPU model. Note, KVM may still ulitmately
* inject a #GP if an access is allowed by userspace, e.g. if KVM doesn't support
* the MSR, or to follow architectural behavior for the MSR.
* 
* By default, KVM operations in KVM_MSR_FILTER_DEFAULT_ALLOW mode with no MSR range
* filters.
* 
* Calling this ioctl with an empty set of ranges (all nmsrs == 0) disables MSR
* filtering. In that mode, KVM_MSR_FILTER_DEFAULT_DENY is invalid and caouses an
* error.
*/
#define KVM_X86_SET_MSR_FILTER CTL_CODE(KVM_DEVICE,0x83C,METHOD_BUFFERED,FILE_ANY_ACCESS)


/*
* i8254 (PIT) has two modes, reinject and !reinject.
*/
#define KVM_REINJECT_CONTROL CTL_CODE(KVM_DEVICE,0x83D,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Returns supported MCE capabilities.The u64 mce_cap parameter
* has the same format as the MSR_IA32_MCG_CAP register. Supported
* capabilities will have the corresponding bits set.
*/
#define KVM_X86_GET_MCE_CAP_SUPPORTED CTL_CODE(KVM_DEVICE,0x83E,METHOD_BUFFERED,FILE_ANY_ACCESS)


/*
* Initialize MCE support for use. The u64 mcg_cap parameter
* has the same format as the MSR_IA32_MCG_CAP register and
* specifies which capabilities should be enabled. The maximum
* supported number of error-reporting banks can be retrived when
* checking for KVM_CAP_MCE. The supported capabilities can be
* retrieved with KVM_X86_GET_MCE_CAP_SUPPORTED.
*/
#define KVM_X86_SETUP_MCE CTL_CODE(KVM_DEVICE,0x83F,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Inject a machine check error (MCE) into the guest.
* 
* If the MCE being reported is an uncorrected error, KVM will
* inject it as an MCE exception into the guest. If the guest 
* MCG_STATUS register reports that an MCE is in progress, KVM
* causes an KVM_EXIT_SHUTDOWN vmexit.
* 
* Otherwise, if the MCE is a corrected error, KVM will just 
* store it in the corresponding bank (provided this bank is
* not holding a previously reported uncorrected error).
*/
#define KVM_X86_SET_MCE CTL_CODE(KVM_DEVICE,0x840,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* If the platform supports creating encrypted VMs then this ioctl can be used
* for issuing platform-specific memory encryption commands to manage those
* encrypted VMs.
* 
* Currently, this ioctl is used for issuing Secure Encrypted Virtualization
* (SEV) commands on AMD Processors. 
*/
#define KVM_MEMORY_ENCRYPT_OP CTL_CODE(KVM_DEVICE,0x841,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* This ioctl can be used to register a guest memory region which may
* contain encrypted data (e.g. guest RAM, SMRAM etc).
* 
* It is used in the SEV-enabled guest. When encryption is enabled, a guest
* memory region may contain encrypted data. The SEV memory encryption
* engine uses a tweak such that two identical plaintext pages, each at
* different locations will have differing ciphertexts. So swapping or
* moving ciphertext of those pages will not result in plaintext being
* swapped. So relocating (or migrating) physical backing pages for the SEV
* guest will require some additional steps.
* 
* Note: The current SEV key management spec doesn't provide commands to
* swap or migrate (move) ciphertext pages. Hence, for now we pin the guest
* memory region registered with the ioctl.
*/
#define KVM_MEMORY_ENCRYPT_REG_REGION CTL_CODE(KVM_DEVICE,0x842,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* This ioctl can be used to unregister the guest memory region registered
* with KVM_MEMORY_ENCRYPT_REG_REGION ioctl above.
*/
#define KVM_MEMORY_ENCRYPT_UNREG_REGION CTL_CODE(KVM_DEVICE,0x843,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* This ioctl copies the vcpu's nested virtualization state from the kernel to
* userspace.
* 
* The maximum size of the state can be retrieved by passing KVM_CAP_NESTED_STATE
* to the KVM_CHECK_EXTENSION ioctl().
*/
#define KVM_GET_NESTED_STATE CTL_CODE(KVM_DEVICE,0x844,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* This copies the vcpu's kvm_nested_state struct from userspace to the kernel.
* 
*/
#define KVM_SET_NESTED_STATE CTL_CODE(KVM_DEVICE,0x845,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* Read special registers from the vcpu.
* This ioctl (when supported) replaces the KVM_GET_SREGS.
*/
#define KVM_GET_SREGS2 CTL_CODE(KVM_DEVICE,0x846,METHOD_BUFFERED,FILE_ANY_ACCESS)

/*
* This ioctl would copy current vcpu's xsave struct to the userspace. It
* copies as many bytes as are returned by KVM_CHECK_EXTENSION(KVM_CAP_XSAVE2).
* The size value returned by KVM_CHECK_EXTENSION(KVM_CAP_XSAVE2) will always be
* at least 4096. Currently, it is only greater than 4096 if a dynamic feature has
* been enabled with arch_prctl(), but this may change in the future.
* 
* The offsets of the state save areas in struct kvm_xsave follow the contets
* of CPUID leaf 0xD on the host.
*/
#define KVM_GET_XSAVE2 CTL_CODE(KVM_DEVICE,0x847,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define KVM_RELEASE_VM		CTL_CODE(KVM_DEVICE,0x849,METHOD_BUFFERED,FILE_ANY_ACCESS)

