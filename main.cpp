#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <netinet/in.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

char **hosts;
int cnt;
int binsearch(char *host,int start,int end)
{
	if(start > end)
		return 0;
	
	int mid = (start+end)/2;
	int result = strcmp(hosts[mid],host);
	if(!result)
		return 1;
	else if(result < 0)
		return binsearch(host,start,mid-1);
	else
		return binsearch(host,mid+1,end);
	
}
/* returns packet id */
int filter (struct nfq_data *tb,u_int32_t *pid)
{

	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	char *data;
    char* banned;
    char* p;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph)
		*pid = ntohl(ph->packet_id);


	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	ret = nfq_get_payload(tb, (unsigned char **)&data);
    
    if (ret == 0)
        return 0;

    p = data + sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr);

    int i;
    

    for(i=0;i<128;i++)
    {
        if(!memcmp(&p[i],"Host",4))
            banned = p + (i + 6);
    }
	
	for(i=0;i<cnt;i++)
	{
    	if(binsearch(hosts[i],0,cnt-1))
    	{
        	printf("\nThis site is banned.\n");
        	return 1;
    	}
	}
    

	return 0;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id;
    
	printf("entering callback\n");
	if(filter(nfa,&id))
    {
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    else
    {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv,i;
	char buf[4096] __attribute__ ((aligned));

    if(argc != 2)
    {
        printf("%s <site list file>\n",argv[0]);
        return 0;
    }

	int size;
	FILE *fp = fopen(argv[1],"r");
	fseek(fp,0,SEEK_END);
	size = ftell(fp);
	fclose(fp);

	char *strs = (char *)malloc(size * sizeof(char));

	fp = fopen(argv[1],"r");
	fread(strs,size,1,fp);
	fclose(fp);

	int ptr = 0;

	for(i=0;i<size;i++)
	{
		if(strs[i]=='\n')
			cnt++;
	}
	cnt +=1;

	hosts = (char **)malloc(cnt * sizeof(char *));

	for(i=0;i<cnt;i++)
		hosts[i] = (char *)malloc(100 * sizeof(char));

	cnt = 0;
	for(i=0;i<size;i++)
	{
		if(strs[i]=='\n')
		{
			memcpy(hosts[cnt],&strs[ptr],i-ptr);
			hosts[cnt][i-ptr] = 0;
			ptr = i+1;
			cnt += 1;
		}
	}
	free(strs);
	
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}


	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}