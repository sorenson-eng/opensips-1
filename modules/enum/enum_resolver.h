
#ifndef ENUM_RESOLVER_MOD_H
#define ENUM_RESOLVER_MOD_H

#include "../../ip_addr.h"

#define DEFAULT_QUERY_TIMEOUT 1000
#define DEFAULT_RETRY_NUMBER 2
#define DEFAULT_ENUM_PORT 53

#define ENUM_PORT_SEP		':'

/* ENUM servers string */
extern int enum_query_tout;
extern int enum_query_retry;

int init_enum_resolver(void);
struct rdata* get_enum_record(union sockaddr_union *su, char *);
int init_enum_servers(void);

#endif
