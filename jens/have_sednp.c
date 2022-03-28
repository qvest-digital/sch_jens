#include <errno.h>
#include <stdio.h>
#include <string.h>

int
main(int argc, char *argv[])
{
	(void)!nice(argv[argc - 1][0]);
	puts(strerrordesc_np(errno));
	return (0);
}
