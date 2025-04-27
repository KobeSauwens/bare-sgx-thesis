#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>

static unsigned int failures;

static void report(const char *str, bool result)
{
	printf("\"%s\": %s\n", str, result ? "PASS" : "FAIL");
	if (!result)
		++failures;
}

static void test_ipv4_good(const char *str, uint32_t exp)
{
	struct in_addr addr;
	int ret;

	ret = inet_pton(AF_INET, str, &addr);
	report(str, ret == 1 && addr.s_addr == htonl(exp));
}

static void test_ipv4_bad(const char *str)
{
	struct in_addr addr;
	int ret;

	ret = inet_pton(AF_INET, str, &addr);
	report(str, ret == 0);
}

static void test_ipv6_good(const char *str, uint32_t exp0, uint32_t exp1,
			   uint32_t exp2, uint32_t exp3)
{
	struct in6_addr addr;
	int ret;

	ret = inet_pton(AF_INET6, str, &addr);
	report(str,
	       ret == 1 && addr.s6_addr32[0] == htonl(exp0) &&
	       addr.s6_addr32[1] == htonl(exp1) &&
	       addr.s6_addr32[2] == htonl(exp2) &&
	       addr.s6_addr32[3] == htonl(exp3));
}

static void test_ipv6_bad(const char *str)
{
	struct in6_addr addr;
	int ret;

	ret = inet_pton(AF_INET6, str, &addr);
	report(str, ret == 0);
}

int main(void)
{
	test_ipv4_good("0.0.0.0", 0);
	test_ipv4_good("255.255.255.255", 0xffffffff);
	test_ipv4_good("127.0.0.1", 0x7f000001);

	test_ipv4_bad("");
	test_ipv4_bad("0.0.0.");
	test_ipv4_bad(".0.0.0");
	test_ipv4_bad("0..0.0");
	test_ipv4_bad("1.2.3.256");
	test_ipv4_bad("256.1.2.3");
	test_ipv4_bad("-1.2.3.4");
	test_ipv4_bad("1.2.3.-4");
	test_ipv4_bad("\xb1.2.3.4");
	test_ipv4_bad(" 1.2.3.4");
	test_ipv4_bad("1 .2.3.4");
	test_ipv4_bad("1. 2.3.4");
	test_ipv4_bad("1.2.3.4 ");
	test_ipv4_bad("1");
	test_ipv4_bad("1.2");
	test_ipv4_bad("1.2.3");
	test_ipv4_bad("0x1.2.3.4");
	test_ipv4_bad("1.2.3.0x4");

	test_ipv6_good("::",
		       0x00000000, 0x00000000, 0x00000000, 0x00000000);
	test_ipv6_good("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		       0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff);
	test_ipv6_good("0123:4567:89ab:cdef:fedc:ba98:7654:3210",
		       0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210);
	test_ipv6_good("0:12:345:6789:abcd:ef0:12:3",
		       0x00000012, 0x03456789, 0xabcd0ef0, 0x00120003);
	test_ipv6_good("fe80::c001:cafe:dead:c0de",
		       0xfe800000, 0x00000000, 0xc001cafe, 0xdeadc0de);

	test_ipv6_bad("");
	test_ipv6_bad(":");
	test_ipv6_bad("1:2:3:4:5:6:7:8:9");
	test_ipv6_bad("1:::2");
	test_ipv6_bad("1::2::3");
	test_ipv6_bad("1.2.3.4");
	test_ipv6_bad("-1::");
	test_ipv6_bad("::-1");
	test_ipv6_bad("10000::");
	test_ipv6_bad("::10000");
	test_ipv6_bad("\xc1::");
	test_ipv6_bad(" ::1");
	test_ipv6_bad("1 ::2");
	test_ipv6_bad("1: 2::3");
	test_ipv6_bad("1: :2");
	test_ipv6_bad("1:: 2");
	test_ipv6_bad("1::2 ");
	/* XXX We should support this format, but currently do not */
	test_ipv6_bad("::ffff:1.2.3.4");

	return failures != 0;
}
