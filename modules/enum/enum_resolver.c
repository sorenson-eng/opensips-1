#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "enum_resolver.h"
#include "../../timer.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../ip_addr.h"
#include "../../resolve.h"


/* timeout mechanism for querying */
static int alarm_timeout;
static int enum_sock = -1;
int enum_query_tout = DEFAULT_QUERY_TIMEOUT;
int enum_query_retry = DEFAULT_RETRY_NUMBER;

static void alarm_handler(int sig)
{
	alarm_timeout = 1;
}

void stop_alarm(void) {
	struct itimerval interval;
	interval.it_interval.tv_usec = 0;
	interval.it_interval.tv_sec = 0;
	interval.it_value.tv_usec = 0;
	interval.it_value.tv_sec = 0;
	alarm_timeout=0;
	setitimer(ITIMER_REAL, &interval, NULL);
}


void start_alarm(void)
{
	struct itimerval new;
	new.it_interval.tv_usec = 0;
	new.it_interval.tv_sec = 0;
	new.it_value.tv_usec = enum_query_tout % 1000;
	new.it_value.tv_sec = enum_query_tout / 1000;
	alarm_timeout=0;
	setitimer(ITIMER_REAL, &new, NULL);
}

int init_enum_resolver(void)
{
	int n = 0;
	struct sockaddr_in si;
	struct sigaction sact;

	LM_DBG("Initiating child\n");

	/* build server */
	memset(&si, 0, sizeof(struct sockaddr_in));
	si.sin_family = AF_INET;
	si.sin_port = htons(0);
	si.sin_addr.s_addr = htonl(INADDR_ANY);

	enum_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (enum_sock < 0) {
		LM_ERR("cannot create socket\n");
		goto error;
	}
	n = 1;
	if (setsockopt(enum_sock, SOL_SOCKET, SO_REUSEADDR, (void*)&n, 
				sizeof(n)) == -1) {
			LM_ERR("setsockopt failed %s\n", strerror(errno));
			goto error;
	}

	if (bind(enum_sock,(struct sockaddr*)&si, sizeof(struct sockaddr_in)) < 0) {
		LM_ERR("cannot bind socket\n");
		goto error;
	}

	/* register SIGALARM handler */
	sigemptyset( &sact.sa_mask );
    	sact.sa_flags = 0;
    	sact.sa_handler = alarm_handler;
    	if (sigaction( SIGALRM, &sact, NULL ) < 0) {
		LM_ERR("cannot isntall SIGALARM signal\n");
		return -1;
	}
	return 0;
error:
	return -1;
}

/* builds and sends naptr query to DNS */
int query_naptr(union sockaddr_union *sock, unsigned char* query,
		unsigned char *buffer, int max_size)
{
	unsigned short qid = rand() & 0xFFFF;
	unsigned short qrpl=0;
	unsigned char *cb, *cq, *endb, *pb = buffer;
	int len, nr, size = 0;
	unsigned int ssize;
	union sockaddr_union su;
	int send_retries, receive_retries;
	
	len = strlen((char*)query);
	if (len > max_size) {
		LM_ERR("query too long\n");
		return -1;
	}
	endb = pb + max_size;
	memset(pb, 0, max_size);
	
	/* query id */
	memcpy(pb, &qid, 2);
	pb += 2;

	/* set recursion query */
	*pb = 1;
	pb += 2;

	/* question count */
	*(++pb) = 1;
	pb++;

	/* skip an, ns and ar count */
	pb += 6;

	/* start copying the query */
	if (pb + len > endb) {
		LM_ERR("query too long \n");
		return -1;
	}
	cb = pb + len;
	cq = query + len - 1;
	nr = 0;

	while (cq >= query) {
		if (*cq == '.') {
			*cb = nr;
			nr = 0;
		} else {
			*cb = *cq;
			nr++;
		}
		cb--; cq--;
	}
	
	if (cb != pb) {
		LM_ERR("BUG - error in parsing (%p-%p)\n", cb, pb);
		return -1;
	}
	*pb = nr;
	pb += len + 1;

	/* set NAPTR type */
	*(++pb) = T_NAPTR;
	pb++;

	/* set IN class */
	*(++pb) = 1;
	size = pb - buffer + 1;

	send_retries = enum_query_retry;
retry:
	LM_INFO("Sending query ; retries = %d", send_retries);
	if (send_retries-- == 0) {
		LM_ERR("enum server does not respond\n");
		return -1;
	}

	ssize = sizeof(struct sockaddr_in);
	/* send query to enum server */
	start_alarm();
	len = sendto(enum_sock, buffer, size, 0, &sock->s, ssize);
	stop_alarm();

	LM_INFO("Post sendto \n");

	if (alarm_timeout) {
		LM_ERR("timeout sending query to ENUM server\n");
		goto retry;
	}
	if (len <= 0) {
		LM_ERR("cannot send query to ENUM server: %d(%s)\n",
				errno, strerror(errno));
		goto retry;
	}

	receive_retries = enum_query_retry;
retry_recv:
	LM_INFO("Ready to receive reply - retries = %d \n", receive_retries);
	if (receive_retries-- == 0) {
		LM_ERR("enum server does not respond\n");
		return -1;
	}

	/* receive response */
	start_alarm();
	len = recvfrom(enum_sock, buffer, max_size, 0, &su.s, &ssize);
	stop_alarm();

	LM_INFO("Post recvfrom \n");
	
	if (alarm_timeout) {
		LM_ERR("timeout receiving query from ENUM server\n");
		goto retry_recv;
	}
	if (len <= 0) {
		if (errno != EINTR) 
			LM_ERR("cannot receive query from ENUM server: %d(%s)\n",
			errno, strerror(errno));
		goto retry_recv;
	}

	memcpy(&qrpl,buffer,2);
	LM_INFO("We've generated query id %hu and received rpl id  %hu \n",qid,qrpl);
	
	/* check to see if the query is valid */
	if (memcmp(&qid, buffer, 2)) {
		LM_ERR("invalid query identifier\n");
		goto retry_recv;
	}
	
	return len;
}

/* XXX: copied from resolve.c - make this public? */
/*! \brief Skips over a domain name in a dns message
 *  (it can be  a sequence of labels ending in \\0, a pointer or
 *   a sequence of labels ending in a pointer -- see rfc1035
 *   returns pointer after the domain name or null on error
 */
unsigned char* dns_skipname(unsigned char* p, unsigned char* end)
{
	while(p<end) {
		/* check if \0 (root label length) */
		if (*p==0){
			p+=1;
			break;
		}
		/* check if we found a pointer */
		if (((*p)&0xc0)==0xc0){
			/* if pointer skip over it (2 bytes) & we found the end */
			p+=2;
			break;
		}
		/* normal label */
		p+=*p+1;
	}
	return (p>=end)?0:p;
}

struct rdata* get_enum_record(union sockaddr_union *su, char *name)
{
	int size;
	int qno, answers_no;
	int r;
	static union dns_query buff;
	unsigned char* p;
	unsigned char* end;
	unsigned short rtype, class, rdlength;
	unsigned int ttl;
	struct rdata* head;
	struct rdata** crt;
	struct rdata** last;
	struct rdata* rd;

	if (!su)
		return get_record(name, T_NAPTR);

	size=query_naptr(su, (unsigned char*)name, buff.buff, sizeof(buff));
	if (size<0) {
		LM_DBG("naptr lookup(%s) failed\n", name);
		goto not_found;
	} else if ((unsigned int)size > sizeof(buff))
		 size=sizeof(buff);
	head=rd=0;
	last=crt=&head;
	
	p=buff.buff+DNS_HDR_SIZE;
	end=buff.buff+size;
	if (p>=end) goto error_boundary;
	qno=ntohs((unsigned short)buff.hdr.qdcount);

	for (r=0; r<qno; r++){
		/* skip the name of the question */
		if ((p=dns_skipname(p, end))==0) {
			LM_ERR("skipname==0\n");
			goto error;
		}
		p+=2+2; /* skip QCODE & QCLASS */
		if (p>=end) {
			//LM_ERR("p>=end\n");
			goto error;
		}
	};
	answers_no=ntohs((unsigned short)buff.hdr.ancount);
	for (r=0; (r<answers_no) && (p<end); r++){
		/*  ignore it the default domain name */
		if ((p=dns_skipname(p, end))==0) {
			LM_ERR("skip_name=0 (#2)\n");
			goto error;
		}
		/* check if enough space is left for type, class, ttl & size */
		if ((p+2+2+4+2)>=end) goto error_boundary;
		/* get type */
		memcpy((void*) &rtype, (void*)p, 2);
		rtype=ntohs(rtype);
		p+=2;
		/* get  class */
		memcpy((void*) &class, (void*)p, 2);
		class=ntohs(class);
		p+=2;
		/* get ttl*/
		memcpy((void*) &ttl, (void*)p, 4);
		ttl=ntohl(ttl);
		p+=4;
		/* get size */
		memcpy((void*)&rdlength, (void*)p, 2);
		rdlength=ntohs(rdlength);
		p+=2;
		/* expand the "type" record  (rdata)*/
		
		rd=(struct rdata*)pkg_malloc(sizeof(struct rdata));
		if (rd==0){
			LM_ERR("out of pkg memory\n");
			goto error;
		}
		rd->type=rtype;
		rd->class=class;
		rd->ttl=ttl;
		rd->next=0;
		if (rtype == T_NAPTR) {
			rd->rdata=(void*) dns_naptr_parser(buff.buff, end, p);
			if(rd->rdata==0) goto error_parse;
			*last=rd;
			last=&(rd->next);
		} else {
			LM_DBG("data type different than naptr\n");
		}
		p+=rdlength;
	}
	return head;
error_boundary:
		LM_ERR("end of query buff reached\n");
		if(head)
			free_rdata_list(head);
		return 0;
error_parse:
		LM_ERR("rdata parse error \n");
		if (rd) pkg_free(rd); /* rd->rdata=0 & rd is not linked yet into
								   the list */
error:
		// LM_ERR("get_record \n");
//		if (head) free_rdata_list(head);
not_found:
	return 0;
}
