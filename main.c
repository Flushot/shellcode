#include <stdio.h> // printf
#include <sys/mman.h> // mmap, mprotect
#include <string.h> // memcpy
#include <unistd.h> // getpagesize
#include <stdlib.h>

#include "shellcode.h"

int main() {
    unsigned char *exec_page;
    size_t exec_page_size, sys_page_size;
    size_t shellcode_size = sizeof(shellcode);

    // Calculate buffer size aligned to page size
    sys_page_size = (size_t)getpagesize();
    exec_page_size = (shellcode_size + sys_page_size - 1) & ~(sys_page_size - 1);

    // Allocate page as R+W (can't make it exectuable yet because of W^X protection)
    printf("Allocating page (%zd bytes for %zd bytes of shellcode)...\n",
           exec_page_size, shellcode_size);
    exec_page = mmap(NULL, exec_page_size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
    if (exec_page == MAP_FAILED) {
        perror("Failed to mmap() memory page");
        return EXIT_FAILURE;
    }

    // Copy shellcode buffer to page
    memcpy(exec_page, shellcode, shellcode_size);

    // Make page executable
    if (mprotect(exec_page, exec_page_size, PROT_READ | PROT_EXEC) != 0) {
        perror("Failed to mark memory page as R+X");
        munmap(exec_page, exec_page_size);
        return EXIT_FAILURE;
    }

    // Execute
    printf("Executing shellcode...\n");
    ((void (*)())exec_page)();

    // Cleanup
    printf("Cleaning up...\n");
    munmap(exec_page, exec_page_size);
    return EXIT_SUCCESS;
}
