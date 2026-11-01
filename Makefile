all: dns

dns: dns.c
	gcc dns.c -o dns