#include <linux/compiler.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/refcount.h>
#include <linux/semaphore.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include <linux/usb/ch9.h>
#include <linux/usb/ch11.h>
#include <linux/usb/cdc.h>
#include <linux/hid.h>

#include <linux/usb/gadgetfs.h>
#include <linux/usb/gadget.h>

#include <uapi/linux/usb/fuzzer.h>

#define	DRIVER_DESC "USB fuzzer"
#define DRIVER_NAME "usb-fuzzer-gadget"

MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_AUTHOR("Andrey Konovalov");
MODULE_LICENSE("GPL");

#if 0
#define print_debug(fmt, args...) pr_err(fmt, ##args)
#else
#define print_debug(fmt, args...)
#endif

/*----------------------------------------------------------------------*/

#define FUZZER_EVENT_QUEUE_SIZE 5

struct fuzzer_event_queue {
	spinlock_t		lock;
	struct semaphore	sema;
	struct usb_fuzzer_event	*events[FUZZER_EVENT_QUEUE_SIZE];
	int			size;
};

static void fuzzer_event_queue_init(struct fuzzer_event_queue *queue)
{
	spin_lock_init(&queue->lock);
	sema_init(&queue->sema, 0);
	queue->size = 0;
}

static int fuzzer_event_queue_add(struct fuzzer_event_queue *queue,
	enum usb_fuzzer_event_type type, size_t length, const void *data)
{
	unsigned long flags;
	struct usb_fuzzer_event *event;
	int i;

	print_debug("uf: fuzzer_event_queue_add: type = %d\n", (int)type);

	spin_lock_irqsave(&queue->lock, flags);

	event = kmalloc(sizeof(*event) + length, GFP_ATOMIC);
	if (!event) {
		spin_unlock_irqrestore(&queue->lock, flags);
		return -ENOMEM;
	}
	event->type = type;
	event->length = length;
	if (event->length)
		memcpy(&event->data[0], data, length);

	switch (event->type) {
	case USB_FUZZER_EVENT_DISCONNECT:
	case USB_FUZZER_EVENT_CONNECT:
		for (i = 0; i < queue->size; i++)
			kfree(queue->events[i]);
		queue->size = 0;
		break;
	case USB_FUZZER_EVENT_CONTROL:
	case USB_FUZZER_EVENT_SUSPEND:
		for (i = 0; i < queue->size; i++) {
			if (queue->events[i]->type != event->type)
				continue;
			print_debug("uf: fuzzer_event_queue_add: dropping event[%d]\n", i);
			kfree(queue->events[i]);
			queue->size--;
			memmove(&queue->events[i], &queue->events[i + 1],
					queue->size - i);
			break;
		}
		break;
	case USB_FUZZER_EVENT_RESUME:
		break;
	default:
		kfree(event);
		spin_unlock_irqrestore(&queue->lock, flags);
		return -EINVAL;
	}

	print_debug("uf: fuzzer_event_queue_add: adding event[%d]\n", (int)queue->size);

	BUG_ON(queue->size >= FUZZER_EVENT_QUEUE_SIZE);
	queue->events[queue->size] = event;
	queue->size++;
	up(&queue->sema);

	spin_unlock_irqrestore(&queue->lock, flags);

	return 0;
}

static struct usb_fuzzer_event *fuzzer_event_queue_fetch(
				struct fuzzer_event_queue *queue)
{
	unsigned long flags;
	struct usb_fuzzer_event *event;

retry:
	if (down_interruptible(&queue->sema) != 0)
		return NULL;
	spin_lock_irqsave(&queue->lock, flags);
	if (queue->size == 0) {
		spin_unlock_irqrestore(&queue->lock, flags);
		goto retry;
	}
	event = queue->events[0];
	queue->size--;
	memmove(&queue->events[0], &queue->events[1], queue->size);
	spin_unlock_irqrestore(&queue->lock, flags);
	return event;
}

static void fuzzer_event_queue_destroy(struct fuzzer_event_queue *queue)
{
	int i;

	for (i = 0; i < queue->size; i++) {
		kfree(queue->events[i]);
	}
	queue->size = 0;
	return;
}

/*----------------------------------------------------------------------*/

#define USB_FUZZER_MAX_ENDPOINTS 32

enum ep_state {
	STATE_EP_DISABLED,
	STATE_EP_ENABLED,
};

struct fuzzer_ep {
	enum ep_state		state;
	struct usb_ep		*ep;
	struct usb_request	*req;
	bool			busy;
	ssize_t			status;
};

enum dev_state {
	STATE_DEV_INVALID = 0,
	STATE_DEV_OPENED,
	STATE_DEV_INITIALIZED,
	STATE_DEV_RUNNING,
	STATE_DEV_CLOSED,
	STATE_DEV_FAILED
};

struct fuzzer_dev {
	refcount_t			count;
	spinlock_t			lock;

	const char			*udc_name;
	struct usb_gadget_driver	driver;

	/* Protected by lock: */
	enum dev_state			state;
	struct usb_gadget		*gadget;
	struct usb_request		*req;
	bool				setup_in_pending;
	bool				setup_out_pending;
	bool				setup_urb_queued;
	struct fuzzer_ep		eps[USB_FUZZER_MAX_ENDPOINTS];

	struct completion		setup_done;

	struct fuzzer_event_queue	queue;
};

static struct fuzzer_dev *dev_new(void)
{
	struct fuzzer_dev *dev;
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return NULL;
	refcount_set(&dev->count, 1);
	spin_lock_init(&dev->lock);
	init_completion(&dev->setup_done);
	fuzzer_event_queue_init(&dev->queue);
	return dev;
}

static inline void dev_get(struct fuzzer_dev *dev)
{
	refcount_inc(&dev->count);
}

static void dev_put(struct fuzzer_dev *dev)
{
	int i;

	if (likely(!refcount_dec_and_test(&dev->count)))
		return;
	if (dev->udc_name)
		kfree(dev->udc_name);
	if (dev->driver.udc_name)
		kfree(dev->driver.udc_name);
	if (dev->req) {
		if (dev->setup_urb_queued)
			usb_ep_dequeue(dev->gadget->ep0, dev->req);
		usb_ep_free_request(dev->gadget->ep0, dev->req);
	}
	fuzzer_event_queue_destroy(&dev->queue);
	for (i = 0; i < USB_FUZZER_MAX_ENDPOINTS; i++) {
		if (dev->eps[i].state != STATE_EP_ENABLED)
			continue;
		usb_ep_disable(dev->eps[i].ep);
		// TODO: usb_ep_dequeue?
		usb_ep_free_request(dev->eps[i].ep, dev->eps[i].req);
		kfree(dev->eps[i].ep->desc);
		dev->eps[i].state = STATE_EP_DISABLED;
	}
	kfree(dev);
	print_debug("uf: dev_put freed the device\n");
}

/*----------------------------------------------------------------------*/

static void fuzzer_ctrl_log(const struct usb_ctrlrequest *ctrl, int vendor)
{
	print_debug("uf: fuzzer_ctrl_log: bRequestType: 0x%x (%s), bRequest: 0x%x, wValue: 0x%x, wIndex: 0x%x, wLength: %d\n",
		ctrl->bRequestType, (ctrl->bRequestType & USB_DIR_IN) ? "IN" : "OUT",
		ctrl->bRequest, ctrl->wValue, ctrl->wIndex, ctrl->wLength);

	switch (ctrl->bRequestType & USB_TYPE_MASK) {
	case USB_TYPE_STANDARD:
		print_debug("uf: fuzzer_ctrl_log: type = USB_TYPE_STANDARD\n");
		break;
	case USB_TYPE_CLASS:
		print_debug("uf: fuzzer_ctrl_log: type = USB_TYPE_CLASS\n");
		break;
	case USB_TYPE_VENDOR:
		print_debug("uf: fuzzer_ctrl_log: type = USB_TYPE_VENDOR\n");
		break;
	default:
		print_debug("uf: fuzzer_ctrl_log: type = unknown = %d\n", (int)ctrl->bRequestType);
		break;
	}

	if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_CLASS) {
		if (vendor == 0x08ca) { // USB_VENDOR_ID_AIPTEK
			switch (ctrl->bRequest) {
			case 0x01: // USB_REQ_GET_REPORT
				print_debug("uf: fuzzer_ctrl_log: req = AIPTEK/USB_REQ_GET_REPORT\n");
				return;
			case 0x09: // USB_REQ_SET_REPORT
				print_debug("uf: fuzzer_ctrl_log: req = AIPTEK/USB_REQ_SET_REPORT\n");
				return;
			}
		}
	}

	// HID class requests.
	if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD) {
		switch (ctrl->bRequest) {
		case USB_REQ_GET_DESCRIPTOR:
			print_debug("uf: fuzzer_ctrl_log: req = USB_REQ_GET_DESCRIPTOR\n");
			switch (ctrl->wValue >> 8) {
			case HID_DT_HID:
				print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = HID_DT_HID\n");
				return;
			case HID_DT_REPORT:
				print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = HID_DT_REPORT\n");
				return;
			case HID_DT_PHYSICAL:
				print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = HID_DT_PHYSICAL\n");
				return;
			}
		}
	}

	// CDC & HUB classes requests.
	if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_CLASS) {
		switch (ctrl->bRequest) {
		case USB_CDC_GET_NTB_PARAMETERS:
			print_debug("uf: fuzzer_ctrl_log: req = USB_CDC_GET_NTB_PARAMETERS\n");
			return;
		case USB_CDC_SET_CRC_MODE:
			print_debug("uf: fuzzer_ctrl_log: req = USB_CDC_SET_CRC_MODE\n");
			return;
		case HUB_SET_DEPTH:
			print_debug("uf: fuzzer_ctrl_log: req = HUB_SET_DEPTH\n");
			return;
		}
	}

	if ((ctrl->bRequestType & USB_TYPE_MASK) != USB_TYPE_STANDARD) {
		print_debug("uf: fuzzer_ctrl_log: req = unknown = 0x%x\n", (int)ctrl->bRequest);
		return;
	}

	switch (ctrl->bRequest) {
	case USB_REQ_GET_DESCRIPTOR:
		print_debug("uf: fuzzer_ctrl_log: req = USB_REQ_GET_DESCRIPTOR\n");
		switch (ctrl->wValue >> 8) {
		case USB_DT_DEVICE:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_DEVICE\n");
			break;
		case USB_DT_CONFIG:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_CONFIG, index = %d\n", (int)(ctrl->wValue & 0xff));
			break;
		case USB_DT_STRING:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_STRING\n");
			break;
		case USB_DT_INTERFACE:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_INTERFACE\n");
			break;
		case USB_DT_ENDPOINT:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_ENDPOINT\n");
			break;
		case USB_DT_DEVICE_QUALIFIER:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_DEVICE_QUALIFIER\n");
			break;
		case USB_DT_OTHER_SPEED_CONFIG:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_OTHER_SPEED_CONFIG\n");
			break;
		case USB_DT_INTERFACE_POWER:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_INTERFACE_POWER\n");
			break;
		case USB_DT_OTG:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_OTG\n");
			break;
		case USB_DT_DEBUG:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_DEBUG\n");
			break;
		case USB_DT_INTERFACE_ASSOCIATION:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_INTERFACE_ASSOCIATION\n");
			break;
		case USB_DT_SECURITY:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_SECURITY\n");
			break;
		case USB_DT_KEY:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_KEY\n");
			break;
		case USB_DT_ENCRYPTION_TYPE:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_ENCRYPTION_TYPE\n");
			break;
		case USB_DT_BOS:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_BOS\n");
			break;
		case USB_DT_DEVICE_CAPABILITY:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_DEVICE_CAPABILITY\n");
			break;
		case USB_DT_WIRELESS_ENDPOINT_COMP:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_WIRELESS_ENDPOINT_COMP\n");
			break;
		case USB_DT_WIRE_ADAPTER:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_WIRE_ADAPTER\n");
			break;
		case USB_DT_RPIPE:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_RPIPE\n");
			break;
		case USB_DT_CS_RADIO_CONTROL:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_CS_RADIO_CONTROL\n");
			break;
		case USB_DT_PIPE_USAGE:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_PIPE_USAGE\n");
			break;
		case USB_DT_SS_ENDPOINT_COMP:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_SS_ENDPOINT_COMP\n");
			break;
		case USB_DT_SSP_ISOC_ENDPOINT_COMP:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_SSP_ISOC_ENDPOINT_COMP\n");
			break;
		case USB_DT_HUB:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_HUB\n");
			break;
		case USB_DT_SS_HUB:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_SS_HUB\n");
			break;
		default:
			print_debug("uf: fuzzer_ctrl_log: USB_REQ_GET_DESCRIPTOR: type = unknown = 0x%x\n", (int)(ctrl->wValue >> 8));
			break;
		}
		break;
	case USB_REQ_SET_CONFIGURATION:
		print_debug("uf: fuzzer_ctrl_log: req = USB_REQ_SET_CONFIGURATION\n");
		break;
	case USB_REQ_GET_CONFIGURATION:
		print_debug("uf: fuzzer_ctrl_log: req = USB_REQ_GET_CONFIGURATION\n");
		break;
	case USB_REQ_SET_INTERFACE:
		print_debug("uf: fuzzer_ctrl_log: req = USB_REQ_SET_INTERFACE\n");
		break;
	case USB_REQ_GET_INTERFACE:
		print_debug("uf: fuzzer_ctrl_log: req = USB_REQ_GET_INTERFACE\n");
		break;
	case USB_REQ_GET_STATUS:
		print_debug("uf: fuzzer_ctrl_log: req = USB_REQ_GET_STATUS\n");
		break;
	case USB_REQ_CLEAR_FEATURE:
		print_debug("uf: fuzzer_ctrl_log: req = USB_REQ_CLEAR_FEATURE\n");
		break;
	case USB_REQ_SET_FEATURE:
		print_debug("uf: fuzzer_ctrl_log: req = USB_REQ_SET_FEATURE\n");
		break;
	default:
		print_debug("uf: fuzzer_ctrl_log: req = unknown = 0x%x\n", (int)ctrl->bRequest);
		break;
	}
}

/*----------------------------------------------------------------------*/

static void gadget_ep0_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct fuzzer_dev *dev = req->context;

	print_debug("uf: gadget_ep0_complete: len: %d, status: %d\n",
			req->length, req->status);


	complete(&dev->setup_done);

	print_debug("uf: gadget_ep0_complete = void\n");
}

static int gadget_bind(struct usb_gadget *gadget,
			struct usb_gadget_driver *driver)
{
	int ret = 0;
	struct fuzzer_dev *dev =
		container_of(driver, struct fuzzer_dev, driver);
	struct usb_request *req;
	unsigned long flags;

	print_debug("uf: gadget_bind: %s vs %s\n", gadget->name, dev->udc_name);

	if (strcmp(gadget->name, dev->udc_name) != 0) {
		ret = -ENODEV;
		goto out;
	}
	set_gadget_data(gadget, dev);
	req = usb_ep_alloc_request(gadget->ep0, GFP_KERNEL);
	if (!req) {
		set_gadget_data(gadget, NULL);
		ret = -ENOMEM;
		goto out;
	}

	spin_lock_irqsave(&dev->lock, flags);
	dev->req = req;
	dev->req->context = dev;
	dev->req->complete = gadget_ep0_complete;
	dev->gadget = gadget;
	spin_unlock_irqrestore(&dev->lock, flags);

	dev_get(dev);

out:
	print_debug("uf: gadget_bind = %d\n", ret);
	return ret;
}

static void gadget_unbind(struct usb_gadget *gadget)
{
	struct fuzzer_dev *dev = get_gadget_data(gadget);
	unsigned long flags;

	print_debug("uf: gadget_unbind\n");

	BUG_ON(!dev);

	spin_lock_irqsave(&dev->lock, flags);
	set_gadget_data(gadget, NULL);
	spin_unlock_irqrestore(&dev->lock, flags);

	dev_put(dev);

	print_debug("uf: gadget_unbind = void\n");
}

static int gadget_setup(struct usb_gadget *gadget,
			const struct usb_ctrlrequest *ctrl)
{
	int ret = 0;
	struct fuzzer_dev *dev = get_gadget_data(gadget);
	unsigned long flags;

	if (!dev) {
		ret = -ENODEV;
		goto out;
	}

	print_debug("uf: gadget_setup\n");

	fuzzer_ctrl_log(ctrl, 0);

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state == STATE_DEV_FAILED) {
		ret = -ENODEV;
		goto out_unlock;
	}
	if (dev->setup_urb_queued) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (dev->setup_in_pending || dev->setup_out_pending) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if ((ctrl->bRequestType & USB_DIR_IN)) {
		dev->setup_in_pending = true;
	} else {
		dev->setup_out_pending = true;
	}

	ret = fuzzer_event_queue_add(&dev->queue,
		USB_FUZZER_EVENT_CONTROL, sizeof(*ctrl), ctrl);
	if (ret < 0) {
		dev->state = STATE_DEV_FAILED;
		goto out_unlock;
	}

out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
out:
	print_debug("uf: gadget_setup = %d\n", ret);
	return ret;
}

static void gadget_disconnect(struct usb_gadget *gadget)
{
	print_debug("uf: gadget_disconnect\n");
	return;
}

static void gadget_suspend(struct usb_gadget *gadget)
{
	print_debug("uf: gadget_suspend\n");
	return;
}

static struct usb_gadget_driver gadget_driver = {
	.function	= DRIVER_DESC,
	.bind		= gadget_bind,
	.unbind		= gadget_unbind,
	.setup		= gadget_setup,
	.reset		= gadget_disconnect,
	.disconnect	= gadget_disconnect,
	.suspend	= gadget_suspend,

	.driver	= {
		.name	= DRIVER_NAME,
	},

	.match_existing_only = 1,
};

/*----------------------------------------------------------------------*/

static int fuzzer_open(struct inode *inode, struct file *fd)
{
	int ret = 0;
	struct fuzzer_dev *dev;

	print_debug("uf: fuzzer_open\n");

	dev = dev_new();
	if (!dev) {
		ret = -ENOMEM;
		goto out;
	}
	dev->state = STATE_DEV_OPENED;
	fd->private_data = dev;

out:
	print_debug("uf: fuzzer_open = %d\n", ret);
	return ret;
}

static int fuzzer_release(struct inode *inode, struct file *fd)
{
	int ret = 0;
	struct fuzzer_dev *dev = fd->private_data;
	unsigned long flags;
	bool unregister = false;

	print_debug("uf: fuzzer_release\n");

	if (!dev) {
		ret = -EBUSY;
		goto out;
	}

	print_debug("uf: fuzzer_release: dev->state = %d\n", (int)dev->state);

	spin_lock_irqsave(&dev->lock, flags);

	// TODO: we might need to unregister with STATE_DEV_FAILED.
	// TODO: set STATE_DEV_FAILED consistently
	if (dev->state == STATE_DEV_RUNNING)
		unregister = true;
	dev->state = STATE_DEV_CLOSED;

	if (!dev->gadget) {
		spin_unlock_irqrestore(&dev->lock, flags);
		ret = -EBUSY;
		goto out_put;
	}

	spin_unlock_irqrestore(&dev->lock, flags);

	if (!unregister)
		goto out_put;

	ret = usb_gadget_unregister_driver(&dev->driver);
	print_debug("uf: usb_gadget_unregister_driver: %d\n", ret);
	WARN_ON(ret != 0);
	dev_put(dev);

out_put:
	dev_put(dev);
out:
	print_debug("uf: fuzzer_release = %d\n", ret);
	return ret;
}

/*----------------------------------------------------------------------*/

#define UDC_NAME_LENGTH_MAX 128

static int fuzzer_ioctl_init(struct fuzzer_dev *dev, unsigned long value)
{
	int ret = 0;
	struct usb_fuzzer_init arg;
	char *udc_driver_name;
	char *udc_device_name;
	unsigned long flags;

	print_debug("uf: fuzzer_ioctl_init\n");

	print_debug("uf: fuzzer_ioctl_init: getting arg\n");
	ret = copy_from_user(&arg, (void *)value, sizeof(arg));
	if (ret)
		goto out;
	print_debug("uf: fuzzer_ioctl_init: got arg\n");

	switch (arg.speed) {
	case USB_SPEED_LOW:
	case USB_SPEED_FULL:
	case USB_SPEED_HIGH:
	case USB_SPEED_SUPER:
		break;
	default:
		arg.speed = USB_SPEED_HIGH;
	}

	udc_driver_name = kmalloc(UDC_NAME_LENGTH_MAX, GFP_KERNEL);
	if (!udc_driver_name) {
		ret = -ENOMEM;
		goto out;
	}
	ret = strncpy_from_user(udc_driver_name, arg.driver_name,
					UDC_NAME_LENGTH_MAX);
	if (ret < 0) {
		kfree(udc_driver_name);
		goto out;
	}
	ret = 0;
	print_debug("uf: fuzzer_ioctl_init: udc_driver_name: %s\n",
			udc_driver_name);

	udc_device_name = kmalloc(UDC_NAME_LENGTH_MAX, GFP_KERNEL);
	if (!udc_device_name) {
		kfree(udc_driver_name);
		ret = -ENOMEM;
		goto out;
	}
	ret = strncpy_from_user(udc_device_name, arg.device_name,
					UDC_NAME_LENGTH_MAX);
	if (ret < 0) {
		kfree(udc_driver_name);
		kfree(udc_device_name);
		goto out;
	}
	ret = 0;
	print_debug("uf: fuzzer_ioctl_init: udc_device_name: %s\n",
			udc_device_name);

	spin_lock_irqsave(&dev->lock, flags);

	if (dev->state != STATE_DEV_OPENED) {
		kfree(udc_driver_name);
		kfree(udc_device_name);
		ret = -EINVAL;
		goto out_unlock;
	}

	dev->udc_name = udc_driver_name;
	memcpy(&dev->driver, &gadget_driver, sizeof(gadget_driver));
	dev->driver.udc_name = udc_device_name;
	dev->driver.max_speed = arg.speed;
	dev->state = STATE_DEV_INITIALIZED;

out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
out:
	print_debug("uf: fuzzer_ioctl_init = %d\n", ret);
	return ret;
}

static int fuzzer_ioctl_run(struct fuzzer_dev *dev, unsigned long value)
{
	int ret = 0;
	unsigned long flags;

	print_debug("uf: fuzzer_ioctl_run\n");

	if (value != 0) {
		ret = -EINVAL;
		goto out;
	}

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_INITIALIZED) {
		ret = -EINVAL;
		goto out_unlock;
	}
	spin_unlock_irqrestore(&dev->lock, flags);

	ret = usb_gadget_probe_driver(&dev->driver);

	spin_lock_irqsave(&dev->lock, flags);
	if (ret != 0) {
		dev->state = STATE_DEV_FAILED;
		goto out_unlock;
	}
	dev->state = STATE_DEV_RUNNING;
	dev_get(dev);

out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
out:
	print_debug("uf: fuzzer_ioctl_run = %d\n", ret);
	return ret;
}

static int fuzzer_ioctl_event_fetch(struct fuzzer_dev *dev, unsigned long value)
{
	int ret = 0;
	struct usb_fuzzer_event arg;
	unsigned long flags;
	struct usb_fuzzer_event *event;
	uint32_t length;

	print_debug("uf: fuzzer_ioctl_event_fetch\n");

	ret = copy_from_user(&arg, (void __user *)value, sizeof(arg));
	if (ret)
		goto out;

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_RUNNING) {
		ret = -EINVAL;
		spin_unlock_irqrestore(&dev->lock, flags);
		goto out;
	}
	if (!dev->gadget) {
		ret = -EBUSY;
		spin_unlock_irqrestore(&dev->lock, flags);
		goto out;
	}
	spin_unlock_irqrestore(&dev->lock, flags);

	event = fuzzer_event_queue_fetch(&dev->queue);
	if (!event) {
		ret = -EINTR;
		goto out;
	}

	length = min(arg.length, event->length);
	ret = copy_to_user((void __user *)value, event,
				sizeof(*event) + length);
	if (ret)
		goto out;

	print_debug("uf: fuzzer_ioctl_event_fetch: length: %u\n", length);

out:
	print_debug("uf: fuzzer_ioctl_event_fetch = %d\n", ret);
	return ret;
}

static int fuzzer_ioctl_ep0_write(struct fuzzer_dev *dev, unsigned long value)
{
	int ret = 0;
	struct usb_fuzzer_ep_io io;
	void *data;
	unsigned long flags;

	print_debug("uf: fuzzer_ioctl_ep0_write\n");

	ret = copy_from_user(&io, (void __user *)value, sizeof(io));
	if (ret)
		goto out;
	if (io.ep != 0) {
		ret = -EINVAL;
		goto out;
	}
	if (!usb_fuzzer_io_flags_valid(io.flags)) {
		ret = -EINVAL;
		goto out;
	}
	if (io.length > PAGE_SIZE) {
		ret = -EINVAL;
		goto out;
	}
	data = memdup_user((void __user *)(value + sizeof(io)), io.length);
	if (IS_ERR(data)) {
		ret = PTR_ERR(data);
		goto out;
	}

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_RUNNING) {
		ret = -EINVAL;
		goto out_unlock;
	}
	if (!dev->gadget) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (!dev->setup_in_pending) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (dev->setup_urb_queued) {
		ret = -EBUSY;
		goto out_unlock;
	}
	BUG_ON(dev->setup_out_pending);
	dev->req->buf = data;
	dev->req->length = io.length;
	dev->req->zero = usb_fuzzer_io_flags_zero(io.flags);
	ret = usb_ep_queue(dev->gadget->ep0, dev->req, GFP_ATOMIC);
	if (ret != 0) {
		kfree(dev->req->buf);
		dev->state = STATE_DEV_FAILED;
		goto out_unlock;
	}
	dev->setup_urb_queued = true;
	spin_unlock_irqrestore(&dev->lock, flags);

	print_debug("uf: fuzzer_ioctl_ep0_write: urb queued, length: %u\n",
			io.length);

	ret = wait_for_completion_interruptible(&dev->setup_done);
	if (ret != 0) {
		print_debug("uf: fuzzer_ioctl_ep0_write: urb interrupted\n");

		spin_lock_irqsave(&dev->lock, flags);
		usb_ep_dequeue(dev->gadget->ep0, dev->req);
		spin_unlock_irqrestore(&dev->lock, flags);

		wait_for_completion(&dev->setup_done);

		spin_lock_irqsave(&dev->lock, flags);

		goto out_flags;
	}

	print_debug("uf: fuzzer_ioctl_ep0_write: urb completed\n");

	spin_lock_irqsave(&dev->lock, flags);
	ret = dev->req->status;

out_flags:
	dev->setup_in_pending = false;
	dev->setup_urb_queued = false;
out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
	kfree(data);
out:
	print_debug("uf: fuzzer_ioctl_ep0_write = %d\n", ret);
	return ret;
}

static int fuzzer_ioctl_ep0_read(struct fuzzer_dev *dev, unsigned long value)
{
	int ret = 0;
	struct usb_fuzzer_ep_io io;
	void *data;
	unsigned long flags;

	print_debug("uf: fuzzer_ioctl_ep0_read\n");

	ret = copy_from_user(&io, (void __user *)value, sizeof(io));
	if (ret)
		goto out;
	if (io.ep != 0) {
		ret = -EINVAL;
		goto out;
	}
	if (!usb_fuzzer_io_flags_valid(io.flags)) {
		ret = -EINVAL;
		goto out;
	}
	if (io.length > PAGE_SIZE) {
		ret = -EINVAL;
		goto out;
	}
	data = kmalloc(io.length, GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto out;
	}

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_RUNNING) {
		ret = -EINVAL;
		goto out_unlock;
	}
	if (!dev->gadget) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (!dev->setup_out_pending) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (dev->setup_urb_queued) {
		ret = -EBUSY;
		goto out_unlock;
	}
	BUG_ON(dev->setup_in_pending);
	dev->req->buf = data;
	dev->req->length = io.length;
	dev->req->zero = usb_fuzzer_io_flags_zero(io.flags);
	ret = usb_ep_queue(dev->gadget->ep0, dev->req, GFP_ATOMIC);
	if (ret != 0) {
		dev->state = STATE_DEV_FAILED;
		goto out_unlock;
	}
	dev->setup_urb_queued = true;
	spin_unlock_irqrestore(&dev->lock, flags);

	print_debug("uf: fuzzer_ioctl_ep0_read: urb queued, length: %u\n",
			io.length);

	ret = wait_for_completion_interruptible(&dev->setup_done);
	if (ret != 0) {
		print_debug("uf: fuzzer_ioctl_ep0_read: urb interrupted\n");

		spin_lock_irqsave(&dev->lock, flags);
		usb_ep_dequeue(dev->gadget->ep0, dev->req);
		spin_unlock_irqrestore(&dev->lock, flags);

		wait_for_completion(&dev->setup_done);

		spin_lock_irqsave(&dev->lock, flags);

		goto out_flags;
	}

	print_debug("uf: fuzzer_ioctl_ep0_read: urb completed\n");

	// TODO: set the right length
	ret = copy_to_user((void __user *)(value + sizeof(io)),
				data, io.length);
	if (ret) {
		spin_lock_irqsave(&dev->lock, flags);
		goto out_flags;
	}

	spin_lock_irqsave(&dev->lock, flags);
	ret = dev->req->status;

out_flags:
	dev->setup_urb_queued = false;
	dev->setup_out_pending = false;
out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
	kfree(data);
out:
	print_debug("uf: fuzzer_ioctl_ep0_read = %d\n", ret);
	return ret;
}

static int check_ep_caps(struct usb_ep *ep, struct usb_endpoint_descriptor *desc)
{
	switch (desc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) {
	case USB_ENDPOINT_XFER_ISOC:
		if (!ep->caps.type_iso)
			return 0;
		break;
	case USB_ENDPOINT_XFER_BULK:
		if (!ep->caps.type_bulk)
			return 0;
		break;
	case USB_ENDPOINT_XFER_INT:
		if (!ep->caps.type_int)
			return 0;
		break;
	default:
		return -EINVAL;
	}

	switch (desc->bEndpointAddress & USB_ENDPOINT_DIR_MASK) {
	case USB_DIR_IN:
		if (!ep->caps.dir_in)
			return 0;
		break;
	case USB_DIR_OUT:
		if (!ep->caps.dir_out)
			return 0;
		break;
	default:
		return -EINVAL;
	}

	return 1;
}

static int fuzzer_ioctl_ep_enable(struct fuzzer_dev *dev, unsigned long value)
{
	int ret = 0, i;
	unsigned long flags;
	struct usb_endpoint_descriptor *desc;
	struct usb_ep *ep = NULL;

	print_debug("uf: fuzzer_ioctl_ep_enable\n");

	desc = memdup_user((void __user *)value, sizeof(*desc));
	if (IS_ERR(desc)) {
		ret = PTR_ERR(desc);
		goto out;
	}

	spin_lock_irqsave(&dev->lock, flags);

	print_debug("uf: fuzzer_ioctl_ep_enable: dev->state = %d\n",
			dev->state);

	if (dev->state != STATE_DEV_RUNNING) {
		ret = -EINVAL;
		goto out_unlock;
	}
	if (!dev->gadget) {
		ret = -EBUSY;
		goto out_unlock;
	}

	for (i = 0; i < USB_FUZZER_MAX_ENDPOINTS; i++) {
		if (dev->eps[i].state == STATE_EP_ENABLED)
			continue;
		break;
	}
	if (i == USB_FUZZER_MAX_ENDPOINTS) {
		ret = -EBUSY;
		goto out_unlock;
	}

	gadget_for_each_ep(ep, dev->gadget) {
		if (ep->enabled)
			continue;
		if (!check_ep_caps(ep, desc))
			continue;
		ep->desc = desc;
		ret = usb_ep_enable(ep);
		if (ret < 0)
			goto out_unlock;
		dev->eps[i].req = usb_ep_alloc_request(ep, GFP_ATOMIC);
		if (!dev->eps[i].req) {
			ret = -ENOMEM;
			goto out_unlock;
		}
		dev->eps[i].ep = ep;
		dev->eps[i].state = STATE_EP_ENABLED;
		ep->driver_data = &dev->eps[i];
		ret = i;
		goto out_unlock;
	}

	kfree(desc);
	ret = -EBUSY;

out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
out:
	print_debug("uf: fuzzer_ioctl_ep_enable = %d\n", ret);
	return ret;
}

static void gadget_ep_io_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct fuzzer_ep *fep = (struct fuzzer_ep *)ep->driver_data;

	if (req->status)
		fep->status = req->status;
	else
		fep->status = req->actual;
	complete((struct completion *)req->context);
}

static int fuzzer_ioctl_ep_write(struct fuzzer_dev *dev, unsigned long value)
{
	int ret = 0;
	unsigned long flags;
	struct usb_fuzzer_ep_io io;
	char *data;
	DECLARE_COMPLETION_ONSTACK(done);

	print_debug("uf: fuzzer_ioctl_ep_write\n");

	ret = copy_from_user(&io, (void __user *)value, sizeof(io));
	if (ret)
		goto out;
	if (io.ep >= USB_FUZZER_MAX_ENDPOINTS) {
		ret = -EINVAL;
		goto out;
	}
	if (!usb_fuzzer_io_flags_valid(io.flags)) {
		ret = -EINVAL;
		goto out;
	}
	if (io.length == 0 || io.length > PAGE_SIZE) {
		ret = -EINVAL;
		goto out;
	}
	data = memdup_user((void __user *)(value + sizeof(io)), io.length);
	if (IS_ERR(data)) {
		ret = PTR_ERR(data);
		goto out;
	}

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_RUNNING) {
		ret = -EINVAL;
		goto out_unlock;
	}
	if (!dev->gadget) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (dev->eps[io.ep].state != STATE_EP_ENABLED) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (dev->eps[io.ep].busy) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (!dev->eps[io.ep].ep->caps.dir_in) {
		ret = -EINVAL;
		goto out_unlock;
	}
	dev->eps[io.ep].busy = true;
	dev->eps[io.ep].req->context = &done;
	dev->eps[io.ep].req->complete = gadget_ep_io_complete;
	dev->eps[io.ep].req->buf = data;
	dev->eps[io.ep].req->length = io.length;
	dev->eps[io.ep].req->zero = usb_fuzzer_io_flags_zero(io.flags);
	ret = usb_ep_queue(dev->eps[io.ep].ep, dev->eps[io.ep].req, GFP_ATOMIC);
	if (ret != 0)
		goto out_unlock;
	spin_unlock_irqrestore(&dev->lock, flags);

	print_debug("uf: fuzzer_ioctl_ep_write: urb queued\n");

	ret = wait_for_completion_interruptible(&done);
	if (ret != 0) {
		spin_lock_irqsave(&dev->lock, flags);
		usb_ep_dequeue(dev->eps[io.ep].ep, dev->eps[io.ep].req);
		spin_unlock_irqrestore(&dev->lock, flags);

		wait_for_completion(&done);

		spin_lock_irqsave(&dev->lock, flags);
		dev->eps[io.ep].busy = false;
		spin_unlock_irqrestore(&dev->lock, flags);

		print_debug("uf: fuzzer_ioctl_ep_write: urb failed\n");

		goto out_free;
	}

	spin_lock_irqsave(&dev->lock, flags);
	ret = dev->eps[io.ep].status;
	dev->eps[io.ep].busy = false;

out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
out_free:
	kfree(data);
out:
	print_debug("uf: fuzzer_ioctl_ep_write = %d\n", ret);
	return ret;
}

static int fuzzer_ioctl_ep_read(struct fuzzer_dev *dev, unsigned long value)
{
	int ret = 0;
	unsigned long flags;
	struct usb_fuzzer_ep_io io;
	char *data;
	DECLARE_COMPLETION_ONSTACK(done);

	print_debug("uf: fuzzer_ioctl_ep_read\n");

	ret = copy_from_user(&io, (void __user *)value, sizeof(io));
	if (ret)
		goto out;
	if (io.ep >= USB_FUZZER_MAX_ENDPOINTS) {
		ret = -EINVAL;
		goto out;
	}
	if (!usb_fuzzer_io_flags_valid(io.flags)) {
		ret = -EINVAL;
		goto out;
	}
	if (io.length == 0 || io.length > PAGE_SIZE) {
		ret = -EINVAL;
		goto out;
	}
	data = kmalloc(io.length, GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto out;
	}

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_RUNNING) {
		ret = -EINVAL;
		goto out_unlock;
	}
	if (!dev->gadget) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (dev->eps[io.ep].state != STATE_EP_ENABLED) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (dev->eps[io.ep].busy) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (!dev->eps[io.ep].ep->caps.dir_out) {
		ret = -EINVAL;
		goto out_unlock;
	}
	dev->eps[io.ep].busy = true;
	dev->eps[io.ep].req->context = &done;
	dev->eps[io.ep].req->complete = gadget_ep_io_complete;
	dev->eps[io.ep].req->buf = data;
	dev->eps[io.ep].req->length = io.length;
	dev->eps[io.ep].req->zero = usb_fuzzer_io_flags_zero(io.flags);
	ret = usb_ep_queue(dev->eps[io.ep].ep, dev->eps[io.ep].req, GFP_ATOMIC);
	if (ret != 0)
		goto out_unlock;
	spin_unlock_irqrestore(&dev->lock, flags);

	print_debug("uf: fuzzer_ioctl_ep_read: urb queued, len: %d\n",
			io.length);

	ret = wait_for_completion_interruptible(&done);
	if (ret != 0) {
		spin_lock_irqsave(&dev->lock, flags);
		usb_ep_dequeue(dev->eps[io.ep].ep, dev->eps[io.ep].req);
		spin_unlock_irqrestore(&dev->lock, flags);

		wait_for_completion(&done);

		spin_lock_irqsave(&dev->lock, flags);
		dev->eps[io.ep].busy = false;
		spin_unlock_irqrestore(&dev->lock, flags);

		goto out_free;
	}

	print_debug("uf: fuzzer_ioctl_ep_read: usb completed\n");

	// TODO: set the right length
	ret = copy_to_user((void __user *)(value + sizeof(io)),
				data, io.length);
	if (ret) {
		spin_lock_irqsave(&dev->lock, flags);
		dev->eps[io.ep].busy = false;
		goto out_unlock;
	}

	spin_lock_irqsave(&dev->lock, flags);
	ret = dev->eps[io.ep].status;
	dev->eps[io.ep].busy = false;

out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
out_free:
	kfree(data);
out:
	print_debug("uf: fuzzer_ioctl_ep_read = %d\n", ret);
	return ret;
}

static int fuzzer_ioctl_configured(struct fuzzer_dev *dev, unsigned long value)
{
	int ret = 0;
	unsigned long flags;

	print_debug("uf: fuzzer_ioctl_configured\n");

	if (value != 0) {
		ret = -EINVAL;
		goto out;
	}

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_RUNNING) {
		ret = -EINVAL;
		goto out_unlock;
	}
	if (!dev->gadget) {
		ret = -EBUSY;
		goto out_unlock;
	}
	usb_gadget_set_state(dev->gadget, USB_STATE_CONFIGURED);

out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
out:
	print_debug("uf: fuzzer_ioctl_configured = %d\n", ret);
	return ret;
}

static int fuzzer_ioctl_vbus_draw(struct fuzzer_dev *dev, unsigned long value)
{
	int ret = 0;
	unsigned long flags;

	print_debug("uf: fuzzer_ioctl_vbus_draw\n");

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->state != STATE_DEV_RUNNING) {
		ret = -EINVAL;
		goto out_unlock;
	}
	if (!dev->gadget) {
		ret = -EBUSY;
		goto out_unlock;
	}
	usb_gadget_vbus_draw(dev->gadget, 2 * value);

out_unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
	print_debug("uf: fuzzer_ioctl_vbus_draw = %d\n", ret);
	return ret;
}

static long fuzzer_ioctl(struct file *fd, unsigned cmd, unsigned long value)
{
	struct fuzzer_dev *dev = fd->private_data;
	int ret;

	print_debug("uf: fuzzer_ioctl: cmd: %u, value: %lx\n", cmd, value);

	if (!dev) {
		ret = -EBUSY;
		goto out;
	}
	switch (cmd) {
	case USB_FUZZER_IOCTL_INIT:
		ret = fuzzer_ioctl_init(dev, value);
		break;
	case USB_FUZZER_IOCTL_RUN:
		ret = fuzzer_ioctl_run(dev, value);
		break;
	case USB_FUZZER_IOCTL_EVENT_FETCH:
		ret = fuzzer_ioctl_event_fetch(dev, value);
		break;
	case USB_FUZZER_IOCTL_EP0_WRITE:
		ret = fuzzer_ioctl_ep0_write(dev, value);
		break;
	case USB_FUZZER_IOCTL_EP0_READ:
		ret = fuzzer_ioctl_ep0_read(dev, value);
		break;
	case USB_FUZZER_IOCTL_EP_ENABLE:
		ret = fuzzer_ioctl_ep_enable(dev, value);
		break;
	case USB_FUZZER_IOCTL_EP_WRITE:
		ret = fuzzer_ioctl_ep_write(dev, value);
		break;
	case USB_FUZZER_IOCTL_EP_READ:
		ret = fuzzer_ioctl_ep_read(dev, value);
		break;
	case USB_FUZZER_IOCTL_CONFIGURE:
		ret = fuzzer_ioctl_configured(dev, value);
		break;
	case USB_FUZZER_IOCTL_VBUS_DRAW:
		ret = fuzzer_ioctl_vbus_draw(dev, value);
		break;
	default:
		ret = -EINVAL;
	}

out:
	print_debug("uf: fuzzer_ioctl = %d\n", ret);
	return ret;
}

/*----------------------------------------------------------------------*/

static const struct file_operations fuzzer_ops = {
	.open =			fuzzer_open,
	.unlocked_ioctl =	fuzzer_ioctl,
	.release =		fuzzer_release,
	.llseek =		no_llseek,
};

static struct dentry *usb_fuzzer_file;

static int __init fuzzer_init(void)
{
	usb_fuzzer_file = debugfs_create_file("usb-fuzzer", 0600,
			NULL, NULL, &fuzzer_ops);
	if (!usb_fuzzer_file) {
		pr_warn("Failed to create usb-fuzzer in debugfs\n");
		return -ENOMEM;
	}
	return 0;
}

static void __exit fuzzer_exit(void)
{
	if (!usb_fuzzer_file)
		return;
	debugfs_remove(usb_fuzzer_file);
	usb_fuzzer_file = NULL;
}

device_initcall(fuzzer_init);
module_exit(fuzzer_exit);
