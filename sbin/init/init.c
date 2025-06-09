
#include <stdio.h>
#include <syscall.h>
int
main(int argc, const char *argv[])
{
    uint64_t status;

    fputs("Init spawning shell\n", stdout);

    const char *args[] = { "/bin/shell", NULL };
    status = OSSpawn("/bin/shell", &args[0]);
    if (status > 100) {
	printf("init: Could not spawn shell %016lx\n", status);
    }

#if 0
    while (1) {
	status = OSWait(0);
	printf("init: Zombie process exited (%016lx)\n", status);
    }
#else
    for (;;)
	    ;
#endif
}

