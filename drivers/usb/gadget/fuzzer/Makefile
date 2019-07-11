# SPDX-License-Identifier: GPL-2.0
#
# USB gadget fuzzer
#

ccflags-y			:= -I$(srctree)/drivers/usb/gadget/
ccflags-y			+= -I$(srctree)/drivers/usb/gadget/udc/
ccflags-y			+= -I$(srctree)/drivers/usb/gadget/function/

obj-$(CONFIG_USB_FUZZER)	+= fuzzer.o
