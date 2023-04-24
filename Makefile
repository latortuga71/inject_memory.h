
.PHONY: all

victim:
	gcc victim.c -o victim


payload:
	nasm -f elf64 -o payload.o payload.asm
	ld -o payload payload.o
	./get_shellcode.sh payload


example:
	gcc example.c -o example
