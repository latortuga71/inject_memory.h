#include <stdio.h>
#define INJECT_MEMORY_IMPLEMENTATION
#define INJECT_MEMORY_DEBUG
#include "inject_memory.h"

unsigned char test_payload[] = "\xeb\x24\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\xb0\x01\x40\xb7\x01\x5e\xb2\x0c\x0f\x05\xcd\x03\xb8\x3c\x00\x00\x00\xbf\x00\x00\x00\x00\x0f\x05\xe8\xd7\xff\xff\xff\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x21";
int print_usage(char* argvzero){
    // add args here
    fprintf(stderr,"Usage: %s\n",argvzero);
    fprintf(stderr,"    --pid");
    fprintf(stderr,"        Inject into pid. \n");      
    fprintf(stderr,"    --elf-exec");
    fprintf(stderr,"        Exec binary in memory using memfd_create. \n");          
    fprintf(stderr,"\n");
    return 1;
}

typedef struct {
    int size;
    char* data;
} Payload;

static Payload read_elf(const char* path){
    FILE* f = fopen(path,"rb");
    fseek(f,0,SEEK_END);
    size_t file_size = ftell(f);
    rewind(f);
    char* payload = (char*)malloc(file_size);
    size_t nread = fread(payload,sizeof(char),file_size,f);
    if (nread != file_size){
        fprintf(stderr,"ERROR: Failed to read file");
        exit(1);
    }
    fclose(f);
    Payload p = {
        .size = file_size,
        .data = payload,
    };
    return p;
}

int main(int argc, char** argv){
    char* binary = argv[0];
    argv++;
    if (*argv == NULL)
        return print_usage(binary);
    else if (strcmp(*argv,"--elf-exec") == 0){
        argv++;
        if (*argv == NULL)
            return print_usage(binary);        
        Payload payload = read_elf(*argv);
        bool worked = inject_memory_memfd_execute_elf(payload.data,payload.size,"TESTER",false,true);
        free(payload.data);
        if (worked){
            printf("Worked!");
        } else {
            printf("Failed!");
        }
        return 0;
    }
    else if (strcmp(*argv,"--pid") == 0){
        argv++;
        if (*argv == NULL)
            return print_usage(binary);
    	bool worked = inject_memory_inject_code(*argv,test_payload,sizeof(test_payload));
		if (worked){
			printf("[+] Worked!\n");
		}else {
			printf("[-] Failed!\n");
		}

    }
    else
        return print_usage(binary);
}