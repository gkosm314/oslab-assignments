            printf("HOST CIOCCRYPT\n");
            struct crypt_op *crypt = elem->out_sg[3].iov_base;
            unsigned char *src = elem->out_sg[4].iov_base;
            unsigned char *iv = elem->out_sg[5].iov_base;
            unsigned char *dst = elem->in_sg[0].iov_base;
            // crypt->src = src;
            memset(&temp_crypt, 0, sizeof(temp_crypt));
            temp_crypt.flags = crypt->flags;
            temp_crypt.ses = crypt->ses;
            temp_crypt.src = src;
            temp_crypt.op = crypt->op;
            temp_crypt.iv = iv;
            // temp_crypt.dst = dst;
            temp_crypt.len = crypt->len;
            if (crypt->op == COP_ENCRYPT) {
                printf("About to encrypt ...\n");
            }
            else if (crypt->op == COP_DECRYPT) {
                printf("About to decrypt ...\n");
            }
            else {
                printf("WRONG CRYPT.OP\n");
            }
            printf("HOST src start\n");
	        for (i=0; i<10; ++i)
			    printf("%i", temp_crypt.src[i]);
		    printf("\nHOST src end\n");
            // *(crypt->iv) = *iv;
            // memcpy(crypt->iv, iv, sizeof(*iv));
            printf("\nHOST after crypt->iv\n");
            // crypt->dst = dst;
            printf("Host CIOCCRYPT ses_id: %u\n", temp_crypt.ses);
            printf("Host CIOCCRYPT len: %u\n", temp_crypt.len);
            ret = ioctl(*fd, CIOCCRYPT, &temp_crypt);
            if (ret < 0)
                fprintf(stderr, "Ioctl error: %s\n", strerror( ret ));
            printf("Host CIOCCRYPT Ret value: %d\n", ret);
            
            printf("Host CIOCCRYPT IV after encrypt:\n");
            for (i=0; i<16; i++)
                printf("%c", temp_crypt.iv[i]);
            printf("IV End\n");
            
            memcpy(dst, temp_crypt.dst, temp_crypt.len);
            ret_val = elem->in_sg[1].iov_base;
            memcpy(ret_val, &ret, sizeof(int));
            printf("Host CIOCCRYPT Exiting switch: %d\n", ret);
            break;