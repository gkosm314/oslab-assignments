debug("CIOCCRYPT");
		copy_ret = copy_from_user(front_crypt, (struct crypt_op *)arg, sizeof(*front_crypt));
		if (copy_ret <0) 
			debug("CIOCCRYPT Copy from user error");
		debug("CIOCCRYPT Copy from user done");
		sg_init_one(&crypt_op_sg, front_crypt, sizeof(*front_crypt));
		sgs[num_out++] = &crypt_op_sg;
		debug("CIOCCRYPT 1");
		src = kzalloc(front_crypt->len, GFP_KERNEL);
		memcpy(src, front_crypt->src, front_crypt->len);
		sg_init_one(&src_sg, src, sizeof(*src));
		sgs[num_out++] = &src_sg;
		debug("CIOCCRYPT 2");
		iv = kzalloc(sizeof(*front_crypt->iv), GFP_KERNEL);
		debug("CIOCCRYPT 5");
		memcpy(iv, front_crypt->iv, sizeof(*front_crypt->iv));
		debug("CIOCCRYPT 6");
		sg_init_one(&iv_sg, iv, sizeof(*iv));
		debug("CIOCCRYPT 7");
		sgs[num_out++] = &iv_sg;
		debug("CIOCCRYPT 3");
		
		sg_init_one(&dst_sg, dst, sizeof(*dst));
		sgs[num_out + num_in++] = &dst_sg;
		debug("CIOCCRYPT 4");
		host_return = kzalloc(sizeof(*host_return), GFP_KERNEL);
		sg_init_one(&host_return_sg, host_return, sizeof(*host_return));
		sgs[num_out + num_in++] = &host_return_sg;

		debug("IV on frontend before switch end:\n");
		for (i=0; i<16; i++)
			debug("%c", front_crypt->iv[i]);
		debug("IV on frontend switch end\n");

		debug("CIOCCRYPT About to exit switch\n");
		break;
