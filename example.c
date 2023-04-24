#include <stdio.h>
#define INJECT_IMPLEMENTATION
//#define INJECT_DEBUG
#include "inject_memory.h"

unsigned char test_payload[] = "\xeb\x24\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\xb0\x01\x40\xb7\x01\x5e\xb2\x0c\x0f\x05\xcd\x03\xb8\x3c\x00\x00\x00\xbf\x00\x00\x00\x00\x0f\x05\xe8\xd7\xff\xff\xff\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x21";
int print_usage(char* argvzero){
    // add args here
    fprintf(stderr,"Usage: %s\n",argvzero);
    fprintf(stderr,"    --pid");
    fprintf(stderr,"        Inject into pid. \n");      
    fprintf(stderr,"\n");
    return 1;
}

int main(int argc, char** argv){
    char* binary = argv[0];
    argv++;
    if (*argv == NULL)
        return print_usage(binary);
    else if (strcmp(*argv,"--pid") == 0){
        argv++;
        if (*argv == NULL)
            return print_usage(binary);
    	bool worked = inject_shellcode(*argv,test_payload,sizeof(test_payload));
		if (worked){
			printf("[+] Worked!\n");
		}else {
			printf("[-] Failed!\n");
		}

    }
    else
        return print_usage(binary);
}