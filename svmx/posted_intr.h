#pragma once


/* Posted-Interrupt Descriptor */
struct pi_desc {
	u32 pir[8];     /* Posted interrupt requested */
	union {
		struct {
			/* bit 256 - Outstanding Notification */
			u16	on : 1,
				/* bit 257 - Suppress Notification */
				sn : 1,
				/* bit 271:258 - Reserved */
				rsvd_1 : 14;
			/* bit 279:272 - Notification Vector */
			u8	nv;
			/* bit 287:280 - Reserved */
			u8	rsvd_2;
			/* bit 319:288 - Notification Destination */
			u32	ndst;
		};
		u64 control;
	};
	u32 rsvd[6];
};

