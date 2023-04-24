#include <stdio.h>
#include <unistd.h>

int main(){
    printf("PID: %d\n",(int)getpid());
    sleep(100000);
    return 0;
}