/*
 * socket-client.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "socket-common.h"

/* Crypto includes */ 
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <crypto/cryptodev.h>

/* Crypto definitions */
#define DATA_SIZE       256
#define BLOCK_SIZE      16
#define KEY_SIZE	16  /* AES128 */



/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

int main(int argc, char *argv[])
{
	int sd, port;
	ssize_t n;
	char stdin_buf[DATA_SIZE];
	char socket_buf[DATA_SIZE];

	memset(stdin_buf, '\0', sizeof(stdin_buf));
	memset(socket_buf, '\0', sizeof(socket_buf));

	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;
	fd_set rfds;
    struct timeval tv;
    int retval;

	/* Crypto required stuff and initializations*/
	struct session_op sess;
	struct crypt_op cryp;
	int cfd;
	unsigned char encrypted[DATA_SIZE],	decrypted[DATA_SIZE],
		iv[BLOCK_SIZE],	key[KEY_SIZE];
	
	/* clear structs */
	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));
	memset(encrypted, '\0', sizeof(encrypted));
	memset(decrypted, '\0', sizeof(decrypted));

	/* Initialize key and iv */ 
	strcpy( (char*) iv, "superdupersecre");
	strcpy( (char*) key, "superdupersecre");

	/* Open /dev/crypto */
	cfd = open("/dev/crypto", O_RDWR);
	if (cfd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

	/*
	 * Get crypto session for AES128
	 */
	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = key;

	if (ioctl(cfd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}





	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");

	memset(stdin_buf, '\0', sizeof(stdin_buf));
	memset(socket_buf, '\0', sizeof(socket_buf));
	memset(encrypted, '\0', sizeof(encrypted));
	memset(decrypted, '\0', sizeof(decrypted));
	for (;;) {
			FD_ZERO(&rfds);
			FD_SET(0, &rfds);
			FD_SET(sd, &rfds);
			retval = select(sd+1, &rfds, NULL, NULL, &tv);
			if (retval == -1)
        		perror("select()");
			
			else if (retval && FD_ISSET(0, &rfds)) { //stdin ready
				memset(stdin_buf, '\0', sizeof(stdin_buf));
				fgets(stdin_buf, sizeof(stdin_buf)-1, stdin);
				// scanf("%255[^\n]", stdin_buf);
				/*
				 * The user can quit by typing "quit"
				 * Then break the loop and shutdown the connection
				 */
				if (strcmp(stdin_buf, "quit\n") == 0)
					break;
				stdin_buf[sizeof(stdin_buf) - 1] = '\0';

				/* Encrypt contents of stdin_buf to encrypted before sending (check the size?) */

				cryp.ses = sess.ses;
				cryp.len = sizeof(stdin_buf);
				cryp.src = (unsigned char *) stdin_buf;
				cryp.dst = encrypted;
				cryp.iv = iv;
				cryp.op = COP_ENCRYPT;

				if (ioctl(cfd, CIOCCRYPT, &cryp)) {
					perror("ioctl(CIOCCRYPT)");
					return 1;
				}

				/* Maybe add null termination to encrypted as well ? */
				// encrypted[sizeof(encrypted) - 1] = '\0';
				/* Write the contents of encrypted buffer */


				if (insist_write(sd, (char *) encrypted, strlen((char *)encrypted)) != strlen((char *) encrypted)) {
					perror("write to remote peer failed");
					break;
				}
				memset(stdin_buf, '\0', sizeof(stdin_buf));
				/* Clear encrypted buffer as well */
				memset(encrypted, '\0', sizeof(encrypted));
			}

			else if (retval && FD_ISSET(sd, &rfds)) {
				// remote newsd ready 
				memset(socket_buf, '\0', sizeof(socket_buf));
				n = read(sd, socket_buf, sizeof(socket_buf));
				if (n <= 0) {
					if (n < 0)
						perror("read from remote peer failed");
					else
						fprintf(stderr, "Peer went away\n");
					break;
				}

				/* Decrypt contents of stdin_buf to decrypted before printing (check the size?) */

				cryp.ses = sess.ses;
				cryp.len = sizeof(socket_buf);
				cryp.src = (unsigned char *) socket_buf;
				cryp.dst = decrypted;
				cryp.iv = iv;
				cryp.op = COP_DECRYPT;

				if (ioctl(cfd, CIOCCRYPT, &cryp)) {
					perror("ioctl(CIOCCRYPT)");
					return 1;
				}

				/* Maybe add null termination to decrypted as well ? */
				// decrypted[sizeof(decrypted) - 1] = '\0';
				/* Write the contents of decrypted buffer */
				printf("Read from remote: %s", (char *) decrypted);
				memset(socket_buf, '\0', sizeof(socket_buf));

				/* Clear decrypted buffer as well */
				memset(decrypted, '\0', sizeof(decrypted));
			}

		}

	/*
	 * Let the remote know we're not going to write anything else.
	 * Try removing the shutdown() call and see what happens.
	 */
	if (shutdown(sd, SHUT_WR) < 0) {
		perror("shutdown");
		exit(1);
	}


	fprintf(stderr, "\nDone.\n");
	return 0;
}
