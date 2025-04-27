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

static void test_good(const char *str, uint32_t exp)
{
	struct in_addr addr;
	int ret;

	ret = inet_aton(str, &addr);
	report(str, ret == 1 && addr.s_addr == htonl(exp));
}

static void test_bad(const char *str)
{
	struct in_addr addr;
	int ret;

	ret = inet_aton(str, &addr);
	report(str, ret == 0);
}

int main(void)
{
	test_good("0.0.0.0", 0);
	test_good("255.255.255.255", 0xffffffff);
	test_good("127.0.0.1", 0x7f000001);

	test_bad("");
	test_bad("0.0.0.");
	test_bad(".0.0.0");
	test_bad("0..0.0");
	test_bad("1.2.3.256");
	test_bad("256.1.2.3");
	test_bad("-1.2.3.4");
	test_bad("1.2.3.-4");
	test_bad("\xb1.2.3.4");
	test_bad(" 1.2.3.4");
	test_bad("1 .2.3.4");
	test_bad("1. 2.3.4");
	test_bad("1.2.3.4 ");
	/* XXX We should maybe support these formats in inet_aton(),
	 * but not in inet_pton() */
	test_bad("1");
	test_bad("1.2");
	test_bad("1.2.3");
	test_bad("0x1.2.3.4");
	test_bad("1.2.3.0x4");

	return failures != 0;
}
