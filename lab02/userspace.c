#include "lunix.h"
// #include "lunix-chredv.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

int main() {
	int cmd = LUNIX_COOKEDCMD;
	char buffer[100];
	char small[2+1];
	int fd;
	int ret;
	/*
	 * Check cooked and raw format using ioctl
	 * (giati eimaste gamatoi)
	 */
	fd = open("/dev/lunix1-temp", O_RDONLY);
	if (fd < 0)
    	printf("Error opening file");
	else {
		int count = 100;
		ssize_t result =read(fd, buffer, count);
		printf("Measurement cooked:\n%s", buffer);

		// Set the needsFormat flag to zero
		ret = ioctl(fd, cmd, 0);
		
		if (ret < 0) {
			printf("Error on ioctl\n");
			printf("%d", ret);
			printf("%s\n", strerror(errno));
		}
		else {
			int count = 100;
			ssize_t result =read(fd, buffer, count);
			printf("Measurement raw:\n%s", buffer);
		}
		ret = ioctl(fd, cmd, 1);
		if (ret < 0) {
			printf("Error on ioctl\n");
			printf("%d", ret);
			printf("%s\n", strerror(errno));
		}
		else {
			int count = 100;
			ssize_t result =read(fd, buffer, count);
			printf("Measurement cooked again:\n%s", buffer);
		}
	}
	close(fd);
	
	/*
	 * Check partial reads of a measurement
	 * (giati eimaste gamatoi)
	 */
	fd = open("/dev/lunix1-temp", O_WRONLY);
	if (fd < 0)
		printf("Error on open\n");
	else {
		ssize_t return_write;
		char *mybuf;
		mybuf = malloc(sizeof (char) * 5);
		sprintf(mybuf, "%s\n", "abcd");
		return_write = write(fd, mybuf, sizeof(mybuf));
		if (return_write < 0) {
			printf("%d\n", return_write);
			printf("%s\n", strerror(errno));
		}
	}
	close(fd);

	
	int fd_2;
	fd_2 = open("/dev/lunix0-batt", O_RDONLY);
	small[2] == '\0';
	while(1) {
		read(fd_2, small, sizeof(small)-1);
		if (small[0] == '\n' || small[1] == '\n')
			break;
		printf("Char: %s\n", small);
		// printf("sizeof small %d\n", sizeof(small));
	}

	return 0;
}