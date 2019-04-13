all:
	sudo g++ dns_attack.c -o dns_attack -Wno-pointer-sign
clean:
	sudo rm dns_attack
