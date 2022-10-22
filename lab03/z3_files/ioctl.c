static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	long ret = 0;
	int err, copy_ret, i;
	unsigned int *ses_id;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, host_fd_sg, ioctl_cmd_sg,
		ses_id_sg, crypt_op_sg, src_sg, iv_sg, dst_sg, *sgs[8];
	struct session_op *front_sess, *host_sess;
	struct crypt_op *front_crypt;
	unsigned int num_out, num_in, len;
#define MSG_LEN 100

	unsigned int *syscall_type;
	int *host_return;
	int *host_fd_;
	unsigned int *cmd_ptr;
	unsigned char *session_key, *src, *dst, *iv;
	struct scatterlist session_key_sg, session_op_sg, host_return_sg;
	debug("Entering");
	debug("Guest ioctl cmd %d\n", cmd);
	host_fd_ = kzalloc(sizeof(*host_fd_), GFP_KERNEL);
	*host_fd_ = crof->host_fd;
	/**
	 * Allocate all data that will be sent to the host.
	 **/

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_IOCTL;

	num_out = 0;
	num_in = 0;
	debug("Frontend 0");
	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	/* ?? */
	sg_init_one(&host_fd_sg, host_fd_, sizeof(*host_fd_));
	sgs[num_out++] = &host_fd_sg;
	debug("Frontend 1");	
	cmd_ptr = kzalloc(sizeof(*cmd_ptr), GFP_KERNEL);
	*cmd_ptr = cmd;
	sg_init_one(&ioctl_cmd_sg, cmd_ptr, sizeof(*cmd_ptr));
	sgs[num_out++] = &ioctl_cmd_sg;
	/**
	 *  Add all the cmd specific sg lists.
	 **/
	
	debug("Frontend 2");
	host_sess = kzalloc(sizeof(*host_sess), GFP_KERNEL);
	front_sess = kzalloc(sizeof(*front_sess), GFP_KERNEL);
	ses_id = kzalloc(sizeof(*ses_id), GFP_KERNEL);
	front_crypt = kzalloc(sizeof(*front_crypt), GFP_KERNEL);
	dst = kzalloc(front_crypt->len, GFP_KERNEL);
	debug("Frontend Before switch");
	switch (cmd) {
		case CIOCGSESSION:
			debug("CIOCGSESSION");
			// sess.keylen
			copy_ret = copy_from_user(front_sess, (struct session_op *)arg, sizeof(*front_sess));
			if (copy_ret <0) 
				debug("Copy from user error");
			
			



			session_key = kzalloc(front_sess->keylen, GFP_KERNEL);
			memcpy(session_key, front_sess->key, front_sess->keylen);
			sg_init_one(&session_key_sg, session_key, sizeof(*session_key));
			sgs[num_out++] = &session_key_sg;
			debug("sg of session_key: %d\n", num_out-1);
			debug("front_sess->cipher: %i\n", front_sess->cipher);
			debug("front_sess->keylen: %d\n", front_sess->keylen);

			// host_sess = kzalloc(sizeof(*host_sess), GFP_KERNEL);
			host_sess->cipher = front_sess->cipher;
			// host_sess->key = session_key;
			host_sess->key = front_sess->key;
			host_sess->keylen = front_sess->keylen;
			debug("host_sess->cipher: %i\n", host_sess->cipher);
			debug("host_sess->keylen: %d\n", host_sess->keylen);
			debug("host_sess->key:\n");
			for (i=0; i<host_sess->keylen; ++i)
				debug("%i", host_sess->key[i]);
			debug("\nKey end\n");
			debug("\nSession key start\n");
			for (i=0; i<host_sess->keylen; ++i)
				debug("%i", session_key[i]);
			debug("\nSession Key end\n");
			sg_init_one(&session_op_sg, host_sess, sizeof(*host_sess));
			sgs[num_out + num_in++] = &session_op_sg;


			host_return = kzalloc(sizeof(*host_return), GFP_KERNEL);
			sg_init_one(&host_return_sg, host_return, sizeof(*host_return));
			sgs[num_out + num_in++] = &host_return_sg;
			break;

		case CIOCFSESSION:
			debug("CIOCFSESSION");

			copy_ret = copy_from_user(ses_id, (unsigned int *)arg, sizeof(*ses_id));
			if (copy_ret <0) 
				debug("Copy from user error");
			debug("CIOCFSESSION ses_id: %u\n", *ses_id);
			sg_init_one(&ses_id_sg, ses_id, sizeof(*ses_id));
			sgs[num_out++] = &ses_id_sg;

			host_return = kzalloc(sizeof(*host_return), GFP_KERNEL);
			sg_init_one(&host_return_sg, host_return, sizeof(*host_return));
			sgs[num_out + num_in++] = &host_return_sg;
			break;

		case CIOCCRYPT:
			debug("CIOCCRYPT");
			copy_ret = copy_from_user(front_crypt, (struct crypt_op *)arg, sizeof(*front_crypt));
			debug("After Copy from user\n");
			if (copy_ret <0) 
				debug("Copy from user error");
			sg_init_one(&crypt_op_sg, front_crypt, sizeof(*front_crypt));
			sgs[num_out++] = &crypt_op_sg;
			debug("Debug 1\n");
			src = kzalloc(front_crypt->len, GFP_KERNEL);
			// memcpy(src, front_crypt->src, front_crypt->len);
			if (copy_from_user(src, front_crypt->src, front_crypt->len))
            	debug("Copy src from user failed");
			debug("Debug 2\n");
			sg_init_one(&src_sg, src, front_crypt->len);
			sgs[num_out++] = &src_sg;
			debug("Debug 3\n");
			iv = kzalloc(16, GFP_KERNEL);
			// memcpy(iv, front_crypt->iv, sizeof(*(front_crypt->iv)));
			if (copy_from_user(iv, front_crypt->iv, 16))
            	debug("Copy iv from user failed");
			sg_init_one(&iv_sg, iv, 16);
			sgs[num_out++] = &iv_sg;
			debug("Debug 4\n");
			sg_init_one(&dst_sg, dst, sizeof(*dst));
			sgs[num_out + num_in++] = &dst_sg;
			debug("Debug 5\n");
			host_return = kzalloc(sizeof(*host_return), GFP_KERNEL);
			sg_init_one(&host_return_sg, host_return, sizeof(*host_return));
			sgs[num_out + num_in++] = &host_return_sg;
			debug("Debug 6\n");
			break;

		default:
			debug("Unsupported ioctl command");

			break;
	}


	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	/* ?? Lock ?? */
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	debug("Back to Frontend\n");
	switch (cmd) {
		case CIOCGSESSION:
			front_sess->ses = host_sess->ses;
			copy_ret = copy_to_user((struct session_op *) arg, (struct session_op *) front_sess, sizeof(*front_sess));
			if (copy_ret <0) 
				debug("Copy from user error");
			debug("CIOCGSESSION: front->ses: %d", front_sess->ses);
			break;
        case CIOCCRYPT: 
			debug("Debug 7\n");
            copy_ret = copy_to_user(((struct crypt_op *) arg)->dst, dst, front_crypt->len);
            if (copy_ret <0) 
                debug("Copy from user error");
            debug("CIOCCRYPT Copy from user returned: %d", copy_ret);
            break; 
		default:
			break;
	}


	// kfree(syscall_type);
	// kfree(front_crypt);
	// kfree(host_fd_);
	// kfree(dst);
	// kfree(cmd_ptr);
	// kfree(host_sess);
	// kfree(front_sess);
	// kfree(ses_id);

	// ret = *host_return;
	debug("Leaving");
	/*Return host return val*/
	return ret;
}