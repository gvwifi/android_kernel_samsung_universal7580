# define_trace.h needs to know how to find our header
CFLAGS_trace.o			:= -I$(src)

udc-core-y			:= core.o trace.o

#
# USB peripheral controller drivers
#
obj-$(CONFIG_USB_GADGET)	+= udc-core.o
obj-$(CONFIG_USB_DUMMY_HCD)	+= dummy_hcd.o
obj-$(CONFIG_USB_S3C2410)	+= s3c2410_udc.o
obj-$(CONFIG_USB_S3C_HSUDC)	+= s3c-hsudc.o
obj-$(CONFIG_USB_S3C_HSOTG)	+= s3c-hsotg.o
obj-$(CONFIG_USB_S3C_OTGD)	+= s3c_udc_otg.o
