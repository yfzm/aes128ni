/* Unit tests for AES-NI implementation.
 */
#include "aes128ni.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <sys/time.h>
static unsigned long get_time() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000 * 1000 + tv.tv_usec;
}

#define C_R(s)  "\033[91;1m" s "\033[0m"
#define C_G(s)  "\033[92;1m" s "\033[0m"

int
main(int argc, char **argv)
{
	unsigned long timer_start, timer_end;
    struct aes128 ctx[1];
    const unsigned char key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

	if (argc < 2) {
		printf("[Usage]: %s memory_size(MB)\n", argv[0]);
		exit(1);
	}
	int memory_size = atoi(argv[1]) * 0x100000;

	/* gen random memory */
	char *rand_mem = (char *)malloc(memory_size);
	int fd = open("/dev/urandom", O_RDONLY);
	read(fd, rand_mem, memory_size);
	close(fd);

	unsigned char *ct = (unsigned char *)malloc(memory_size);
	unsigned char *xt = (unsigned char *)malloc(memory_size);

    aes128_init(ctx, key);

	timer_start = get_time();
	for (unsigned long offset = 0; offset < memory_size; offset += AES128_BLOCKLEN) {
		aes128_encrypt(ctx, ct + offset, rand_mem + offset);
	}
	timer_end = get_time();
	printf("encryption time: %ld us\n", timer_end - timer_start);

	timer_start = get_time();
	for (unsigned long offset = 0; offset < memory_size; offset += AES128_BLOCKLEN) {
		aes128_decrypt(ctx, xt + offset, ct + offset);
	}
	timer_end = get_time();
	printf("decryption time: %ld us\n", timer_end - timer_start);

    if (memcmp(xt, rand_mem, sizeof(ct)))
        puts(C_R("FAIL") ": not matching");
    else
        puts(C_G("PASS") ": correct");
}
