#include <errno.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include "ares.h"


/* --- Macros --- */
#define RUN_TEST(name) \
	if (!setjmp(ctx.env)) \
		test_##name(&ctx.state); \
	else \
		fprintf(stderr, "Test %s failed\n", #name)

#define TEST(name) \
	void test_##name(void **state)

#define TEST_CONTEXT (test_context)

#define ASSERT(expr) \
	if (!(expr)) { \
		++TEST_CONTEXT->num_errors; \
		fprintf(stderr, "assertion failed: %s\n", #expr); \
		longjmp(TEST_CONTEXT->env, 0); \
	}

#define ASSERT_EQUALS(real, expected) \
	if ((real) != (expected)) { \
		++TEST_CONTEXT->num_errors; \
		fprintf(stderr, "assertion failed: real %s != expected %s\n", #real, #expected); \
		longjmp(TEST_CONTEXT->env, 0); \
	}


/* --- Types --- */
struct test_context {
	void *state;
	jmp_buf env;
	int num_errors;
};


/* --- Data --- */
static struct test_context *test_context;


static void agai_numeric_localhost_callback(void *arg, int status, int timeouts, struct ares_addrinfo *result)
{
	ASSERT_EQUALS(status, ARES_SUCCESS);
	ASSERT_EQUALS(timeouts, 0);
	ASSERT(result);
	ASSERT_EQUALS(result->ai_family, AF_INET);
	ASSERT_EQUALS(result->ai_addrlen, sizeof(struct sockaddr_in));
	ASSERT(result->ai_addr);
	ASSERT_EQUALS(result->ai_addr->sa_family, AF_INET);
	ASSERT_EQUALS(((struct sockaddr_in*) result->ai_addr)->sin_addr.s_addr, htonl(INADDR_LOOPBACK));
	ASSERT_EQUALS(((struct sockaddr_in*) result->ai_addr)->sin_port, 0);
	ASSERT(!result->ai_canonname);
	ASSERT(!result->ai_next);
	(*((int*) arg))++;
}

TEST(agai_numeric_localhost)
{
	ares_channel channel;
	struct ares_addrinfo hints;
	int callbacks = 0;

	ASSERT(!ares_init(&channel));
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = ARES_AI_NUMERICHOST;
	ares_getaddrinfo(channel, "127.0.0.1", NULL, &hints, agai_numeric_localhost_callback, &callbacks);
	ASSERT_EQUALS(callbacks, 1);
	ares_destroy(channel);
}

static void agai_numeric_localhost_inet6_callback(void *arg, int status, int timeouts, struct ares_addrinfo *result)
{
	ASSERT_EQUALS(status, ARES_ENONAME);
	(*((int*) arg))++;
}

TEST(agai_numeric_localhost_inet6)
{
	ares_channel channel;
	struct ares_addrinfo hints;
	int callbacks = 0;

	ASSERT(!ares_init(&channel));
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_flags = ARES_AI_NUMERICHOST;
	ares_getaddrinfo(channel, "127.0.0.1", NULL, &hints, agai_numeric_localhost_inet6_callback, &callbacks);
	ASSERT_EQUALS(callbacks, 1);
	ares_destroy(channel);
}

static void agai_nonnumeric_localhost_callback(void *arg, int status, int timeouts, struct ares_addrinfo *result)
{
	ASSERT_EQUALS(status, ARES_ENONAME);
	(*((int*) arg))++;
}

TEST(agai_nonnumeric_localhost)
{
	ares_channel channel;
	struct ares_addrinfo hints;
	int callbacks = 0;

	ASSERT(!ares_init(&channel));
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = ARES_AI_NUMERICHOST;
	ares_getaddrinfo(channel, "localhost", NULL, &hints, agai_nonnumeric_localhost_callback, &callbacks);
	ASSERT_EQUALS(callbacks, 1);
	ares_destroy(channel);
}

int main(int argc, char **argv)
{
	struct test_context ctx;

	memset(&ctx, 0, sizeof(ctx));
	test_context = &ctx;

	RUN_TEST(agai_numeric_localhost);
	RUN_TEST(agai_numeric_localhost_inet6);
	RUN_TEST(agai_nonnumeric_localhost);

	test_context = NULL;

	return ctx.num_errors;
}
