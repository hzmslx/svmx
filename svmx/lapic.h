#pragma once

struct kvm_lapic {
	unsigned long base_address;
	//struct kvm_io_device dev;
	//struct kvm_timer lapic_timer;
	u32 divide_count;
	struct kvm_vcpu* vcpu;
	bool apicv_active;
	bool sw_enabled;
	bool irr_pending;
	bool lvt0_in_nmi_mode;
	/* Number of bits set in ISR. */
	s16 isr_count;
	/* The highest vector set in ISR; if -1 - invalid, must scan ISR. */
	int highest_isr_cache;
	/**
	 * APIC register page.  The layout matches the register layout seen by
	 * the guest 1:1, because it is accessed by the vmx microcode.
	 * Note: Only one register, the TPR, is used by the microcode.
	 */
	void* regs;
	gpa_t vapic_addr;
	//struct gfn_to_hva_cache vapic_cache;
	unsigned long pending_events;
	unsigned int sipi_vector;
	int nr_lvt_entries;
};

static inline bool lapic_in_kernel(struct kvm_vcpu* vcpu)
{
	UNREFERENCED_PARAMETER(vcpu);
	return TRUE;
}

static inline u32 __kvm_lapic_get_reg(char* regs, int reg_off)
{
	return *((u32*)(regs + reg_off));
}

static inline u32 kvm_lapic_get_reg(struct kvm_lapic* apic, int reg_off)
{
	return __kvm_lapic_get_reg(apic->regs, reg_off);
}

u64 kvm_lapic_get_cr8(struct kvm_vcpu* vcpu);
int kvm_lapic_find_highest_irr(struct kvm_vcpu* vcpu);
