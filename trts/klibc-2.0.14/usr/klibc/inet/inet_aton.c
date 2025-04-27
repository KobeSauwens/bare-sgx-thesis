/*
 * inet/inet_aton.c
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>

int inet_aton(const char *str, struct in_addr *addr)
{
	int i = 0, digits = 0, val = 0;
	union {
		uint8_t	 b[4];
		uint32_t l;
	} a;
	char ch;

	for (;;) {
		ch = *str++;
		if (ch == (i == 3 ? 0 : '.')) {
			if (digits == 0)
				return 0;
			a.b[i] = val;
			if (++i == 4)
				break;
			digits = 0;
			val = 0;
		} else if (isdigit((unsigned char)ch)) {
			digits++;
			val = val * 10 + (ch - '0');
			if (val > 0xff)
				return 0;
		} else {
			return 0;
		}
	}

	addr->s_addr = a.l;
	return 1;
}
