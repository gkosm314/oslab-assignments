/*
 * Virtio Cryptodev Device
 *
 * Implementation of virtio-cryptodev qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr> 
 * Konstantinos Papazafeiropoulos <kpapazaf@cslab.ece.ntua.gr>
 *
 */

#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "hw/qdev.h"
#include "hw/virtio/virtio.h"
#include "standard-headers/linux/virtio_ids.h"
#include "hw/virtio/virtio-cryptodev.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

static uint64_t get_features(VirtIODevice *vdev, uint64_t features,
                             Error **errp)
{
    DEBUG_IN();
    return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
    DEBUG_IN();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
    DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
    DEBUG_IN();
}

static void vser_reset(VirtIODevice *vdev)
{
    DEBUG_IN();
}

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtQueueElement *elem;
    unsigned int *syscall_type, *ioctl_cmd;
    struct crypt_op *temp_from_frontend;
    int *fd;
    int i, ret;
    int *ret_val;
    DEBUG_IN();
    unsigned char *src, *dst, *iv;
    elem = virtqueue_pop(vq, sizeof(VirtQueueElement));
    if (!elem) {
        DEBUG("No item to pop from VQ :(");
        return;
    } 

    DEBUG("I have got an item from VQ :)");

    syscall_type = elem->out_sg[0].iov_base;
    switch (*syscall_type) {
    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_OPEN:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_OPEN");
        /* ?? */
        fd = elem->in_sg[0].iov_base;
        int temp = open("/dev/crypto", O_RDWR);
        // *fd = temp;
        memcpy(fd, &temp, sizeof(temp));
        printf("Return from open on host: %d", *fd);
        break;

    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_CLOSE:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_CLOSE");
        /* ?? */
        fd = elem->out_sg[1].iov_base;
        close(*fd);
        printf("Close on host for fd: %d", *fd);
        break;

    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_IOCTL:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_IOCTL");
        /* ?? */
        fd = elem->out_sg[1].iov_base;
        ioctl_cmd = elem->out_sg[2].iov_base;
        printf("Ioctl_cmd: %d\n", *ioctl_cmd);
        switch (*ioctl_cmd) {
        case CIOCGSESSION:;
            unsigned char *session_key = elem->out_sg[3].iov_base;
            struct session_op *sess = elem->in_sg[0].iov_base;
            printf("Session HOST Keylen: %d\n", sess->keylen);
            printf("Session Key start\n");
	        for (i=0; i<sess->keylen; ++i)
			    printf("%i", session_key[i]);
		    printf("\nSession Key end\n");
            sess->key = session_key;
            // memcpy(&sess->key, session_key, sizeof(*session_key));
            // printf("Key start\n");
	        for (i=0; i<sess->keylen; ++i)
			    printf("%i", sess->key[i]);
		    printf("\nKey end\n");
            printf("Session ID Cipher: %i\n", sess->cipher);
            ret = ioctl(*fd, CIOCGSESSION, sess);
            if (ret < 0)
                fprintf(stderr, "Ioctl error: %s\n", strerror( ret ));
            
            printf("Ret value: %d\n", ret);
            printf("Session ID HOST: %d\n", sess->ses);
            ret_val = elem->in_sg[1].iov_base;
            memcpy(ret_val, &ret, sizeof(int));
            break;
        case CIOCFSESSION:;

            __u32 *ses_id = elem->out_sg[3].iov_base;

            printf("Host CIOCFSESSION ses_id: %u\n", *ses_id);
            ret = ioctl(*fd, CIOCFSESSION, ses_id);
            if (ret < 0){
                printf("Error on CIOCFSESSION");
                fprintf(stderr, "Ioctl error: %s\n", strerror( ret ));
            }
            
            printf("Host CIOCFSESSION Ret value: %d\n", ret);
            ret_val = elem->in_sg[0].iov_base;
            memcpy(ret_val, &ret, sizeof(int));
            break;

        case CIOCCRYPT:;
            printf("HOST CIOCCRYPT\n");
            temp_from_frontend = elem->out_sg[3].iov_base;
           
            src = elem->out_sg[4].iov_base;
            iv = elem->out_sg[5].iov_base;
            dst = elem->in_sg[0].iov_base;
            ret_val = elem->in_sg[1].iov_base;
            // temp_from_frontend->dst = malloc(temp_from_frontend->len);
            // memset(temp_from_frontend->dst, 0, temp_from_frontend->len);
            temp_from_frontend->src = src;
            temp_from_frontend->dst = dst;
            temp_from_frontend->iv = iv;
            printf("Before ioctl\n");
            *ret_val = ioctl(*fd, CIOCCRYPT, temp_from_frontend);
            if (*ret_val){
                printf("Error on CIOCCRYPT ioctl\n");
                printf("Ioctl error: %s\n", strerror(*ret_val));
            }

            


            break;
        default:
            printf("Unknown ioctl command :(");
            break;
        }

        
        // unsigned char *output_msg = elem->out_sg[1].iov_base;
        // unsigned char *input_msg = elem->in_sg[0].iov_base;
        // memcpy(input_msg, "Host: Welcome to the virtio World!", 35);
        // printf("Guest says: %s\n", output_msg);
        // printf("We say: %s\n", input_msg);
        break;

    default:
        DEBUG("Unknown syscall_type");
        break;
    }
    printf("Before virtqueue_push\n");
    virtqueue_push(vq, elem, 0);
    printf("Between\n");
    virtio_notify(vdev, vq);
    printf("Before g_free\n");
    g_free(elem);
    printf("After g_free\n");
}

static void virtio_cryptodev_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

    DEBUG_IN();

    virtio_init(vdev, "virtio-cryptodev", VIRTIO_ID_CRYPTODEV, 0);
    virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_cryptodev_unrealize(DeviceState *dev, Error **errp)
{
    DEBUG_IN();
}

static Property virtio_cryptodev_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_cryptodev_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

    DEBUG_IN();
    dc->props = virtio_cryptodev_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_cryptodev_realize;
    k->unrealize = virtio_cryptodev_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
}

static const TypeInfo virtio_cryptodev_info = {
    .name          = TYPE_VIRTIO_CRYPTODEV,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCryptodev),
    .class_init    = virtio_cryptodev_class_init,
};

static void virtio_cryptodev_register_types(void)
{
    type_register_static(&virtio_cryptodev_info);
}

type_init(virtio_cryptodev_register_types)
