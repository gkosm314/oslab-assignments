            back_crypt.len = temp_from_frontend->len;
            back_crypt.ses = temp_from_frontend->ses;
            back_crypt.flags = temp_from_frontend->flags;
            back_crypt.op = temp_from_frontend->op;
            back_crypt.src = elem->out_sg[4].iov_base;
            back_crypt.iv = elem->out_sg[5].iov_base;
            back_crypt.dst = elem->in_sg[0].iov_base;
            




            struct crypt_op *temp_from_frontend = elem->out_sg[3].iov_base;
            temp_from_frontend->src = elem->out_sg[4].iov_base;
            temp_from_frontend->iv = elem->out_sg[5].iov_base;
            // temp_from_frontend->dst = elem->in_sg[0].iov_base;
            temp_from_frontend->dst = malloc(temp_from_frontend->len);
            memset(temp_from_frontend->dst, 0, temp_from_frontend->len);




                        struct crypt_op *temp_from_frontend = malloc(sizeof (*(elem->out_sg[3].iov_base)));
            // memset(temp_from_frontend, 0, sizeof(*temp_from_frontend));
            memset(temp_from_frontend, 0, sizeof (*(elem->out_sg[3].iov_base)));
            printf("CIOCCRYPT 1\n");
            memcpy(temp_from_frontend, elem->out_sg[3].iov_base, sizeof (*(elem->out_sg[3].iov_base)));
            printf("CIOCCRYPT 2\n");
            temp_from_frontend->src = malloc(temp_from_frontend->len);
            printf("CIOCCRYPT 3\n");
            temp_from_frontend->iv = malloc(sizeof(*(elem->out_sg[5].iov_base)));
            printf("CIOCCRYPT 4\n");

            // memcpy(temp_from_frontend->src, elem->out_sg[4].iov_base, sizeof(*(elem->out_sg[4].iov_base)));
            *(temp_from_frontend->src) = *(elem->out_sg[4].iov_base);
            printf("HOST src start\n");
	        for (i=0; i<15; ++i)
			    printf("%i", temp_from_frontend->src[i]);
		    printf("\nHOST src end\n");
            printf("CIOCCRYPT 5\n");
            // memcpy(temp_from_frontend->iv, elem->out_sg[5].iov_base, sizeof(*(elem->out_sg[5].iov_base)));
            *(temp_from_frontend->iv) = *(elem->out_sg[5].iov_base);
            printf("CIOCCRYPT 6\n");
            // temp_from_frontend->dst = elem->in_sg[0].iov_base;
            temp_from_frontend->dst = malloc(temp_from_frontend->len);
            printf("CIOCCRYPT 7\n");
            memset(temp_from_frontend->dst, 0, temp_from_frontend->len);
            printf("Before ioctl\n");
            ret = ioctl(*fd, CIOCCRYPT, temp_from_frontend);
            if (ret < 0){
                printf("Error on CIOCCRYPT ioctl\n");
                printf("Ioctl error: %s\n", strerror(ret));
            }
            printf("HOST CIOCCRYPT dst start\n");
            for (i=0; i<temp_from_frontend->len; ++i)
                printf("%u", (temp_from_frontend->dst)[i]);
            printf("\nHOST CIOCCRYPT dst start\n");
            memcpy(elem->in_sg[0].iov_base, temp_from_frontend->dst, sizeof(*(temp_from_frontend->dst)));
            ret_val = elem->in_sg[1].iov_base;
            memcpy(ret_val, &ret, sizeof(int));