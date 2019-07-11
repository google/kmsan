#ifndef _UAPI__LINUX_USB_FUZZER_H
#define _UAPI__LINUX_USB_FUZZER_H

#include <asm/ioctl.h>
#include <linux/types.h>
#include <linux/usb/ch9.h>

enum usb_fuzzer_event_type {
	USB_FUZZER_EVENT_INVALID,
	USB_FUZZER_EVENT_CONNECT,
	USB_FUZZER_EVENT_DISCONNECT,
	USB_FUZZER_EVENT_SUSPEND,
	USB_FUZZER_EVENT_RESUME,
	USB_FUZZER_EVENT_CONTROL,
};

struct usb_fuzzer_event {
	uint32_t	type;
	uint32_t	length;
	char		data[0];
};

struct usb_fuzzer_init {
	uint64_t	speed;
	const char	*driver_name;
	const char	*device_name;
};

#define USB_FUZZER_IO_FLAGS_ZERO	0x0001
#define USB_FUZZER_IO_FLAGS_MASK	0x0001

static int usb_fuzzer_io_flags_valid(uint16_t flags)
{
	return (flags & ~USB_FUZZER_IO_FLAGS_MASK) == 0;
}

static int usb_fuzzer_io_flags_zero(uint16_t flags)
{
	return (flags & USB_FUZZER_IO_FLAGS_ZERO);
}

struct usb_fuzzer_ep_io {
	uint16_t	ep;
	uint16_t	flags;
	uint32_t	length;
	char		data[0];
};


#define USB_FUZZER_IOCTL_INIT		_IOW('U', 0, struct usb_fuzzer_init)
#define USB_FUZZER_IOCTL_RUN		_IO('U', 1)

#define USB_FUZZER_IOCTL_EVENT_FETCH	_IOR('U', 2, struct usb_fuzzer_event)

#define USB_FUZZER_IOCTL_EP0_WRITE	_IOW('U', 3, struct usb_fuzzer_ep_io)
#define USB_FUZZER_IOCTL_EP0_READ	_IOWR('U', 4, struct usb_fuzzer_ep_io)

#define USB_FUZZER_IOCTL_EP_ENABLE	_IOW('U', 5, struct usb_endpoint_descriptor)
// TODO: USB_FUZZER_IOCTL_EP_DISABLE
#define USB_FUZZER_IOCTL_EP_WRITE	_IOW('U', 7, struct usb_fuzzer_ep_io)
#define USB_FUZZER_IOCTL_EP_READ	_IOWR('U', 8, struct usb_fuzzer_ep_io)

#define USB_FUZZER_IOCTL_CONFIGURE	_IO('U', 9)
#define USB_FUZZER_IOCTL_VBUS_DRAW	_IOW('U', 10, uint32_t)

// TODO: USB_FUZZER_IOCTL_SET_HALT
// TODO: USB_FUZZER_IOCTL_CLEAR_HALT

#endif /* _UAPI__LINUX_USB_FUZZER_H */
