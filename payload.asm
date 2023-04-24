section .text
    global _start

_start:
    jmp short ending

    main_func:
        xor rax, rax;
        xor rdi, rdi;
        xor rsi, rsi;
        xor rdx, rdx;
        mov al, 1   ; syswrite
        mov dil, 1  ; stodut
        pop rsi     ;
        mov dl, 12  ;
        syscall;
        int 3;
        mov rax, 60;
        mov rdi, 0;
        syscall;
    ending:
        call main_func
        db "Hello World!"