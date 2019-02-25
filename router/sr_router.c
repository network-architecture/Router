/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  
  uint16_t my_ethertype = ethertype(packet);
	switch (my_ethertype) {

	case ethertype_ip:
		printf("The packet is a data packet\n");
		sr_handle_ip(sr, packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t), interface);
		return;
	case ethertype_arp:
		printf("The packet is an ARP request/reply\n");
		handle_arpreply(sr, packet);
	}

}/* end sr_ForwardPacket */

/* Handles sending out ARP requests at the correct time intervals */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *request, struct sr_arpcache *cache){
	if(difftime(time(NULL), request->sent)>1.0){
		if(request->times_sent >= 5){
			send_icmp_pkt(sr, request->packets->buf, icmp_unreachable, icmp_dest_host);
			sr_arpreq_destroy(cache,request);
		}
		else{
			send_arpreq(sr, request);
			request->sent = time(NULL);
			request->times_sent++;
		}
	}
}

/* Iterate through and send all packets of a request */
void send_reqpack(struct sr_arpreq *request, struct sr_instance* sr){
	printf("Sending request packets\n");
	struct sr_packet *current = request->packets;
	if(current!=NULL){
		sr_send_packet(sr, current->buf, current->len, current->iface);
	}
	struct sr_packet *next = NULL;
	if(current!=NULL && current->next!=NULL){
		next = current->next;
	}
	while(next!=NULL){
		current = next;
		next = current->next;
		sr_send_packet(sr, current->buf, current->len, current->iface);
	}
}

/* Handle when an ARP reply is received */
void handle_arpreply(struct sr_instance* sr, uint8_t * packet){
	struct sr_arpcache arpcache = sr->cache;
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet);
    struct sr_arpreq *request = sr_arpcache_insert(&arpcache, arp_hdr->ar_sha, arp_hdr->ar_sip);
	if(request != NULL){
		printf("ARP found in cache\n");
	    send_reqpack(request, sr);
		sr_arpreq_destroy(&arpcache,request);
	}
	else{
		printf("ARP not found in cache\n");
	}
}

/* Sends an ARP request */
void send_arpreq(struct sr_instance* sr, struct sr_arpreq *request){
	printf("Sending ARP request\n");
	uint8_t *buf = malloc(56*sizeof(uint8_t));
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
	/* TODO FILL WITH DATA */
	sr_send_packet(sr, buf , 56 , request->packets->iface);
}

void sr_handle_ip(struct sr_instance* sr, uint8_t * buf, unsigned int len, const char* iface) {

	printf("Receiving IP\n");
	sr_ip_hdr_t* my_ip = (sr_ip_hdr_t*)buf;
	/* check min length */
	if (len < sizeof(sr_ip_hdr_t)) {
		printf("Packet too small\n");
		return;
	}
	/* check checksum */
	uint16_t received_cksum = ntohs(my_ip->ip_sum);
	my_ip->ip_sum = 0;
	uint16_t calculated_cksum = ntohs(cksum(my_ip, sizeof(sr_ip_hdr_t)));  
	if (received_cksum != calculated_cksum) {
		printf("Checksum wrong\n");
		return;
	}
	
	
	uint8_t my_ttl = my_ip->ip_ttl;
	if (my_ttl <= 1) {
		/* send ICMP packet: timeout */
		printf("TTL is zero\n");
		send_icmp_pkt(sr, buf, icmp_time_exceeded, icmp_ttl_zero); 
		return;
	}
	
	/* my_ip->ip_ttl = ttl - 1; */
	my_ip->ip_ttl--;
	my_ip->ip_sum = htons(cksum(my_ip, sizeof(sr_ip_hdr_t)));
	uint32_t my_addr = ntohs(my_ip->ip_dst);
	struct sr_if* to_local_interface = sr->if_list;
	while(to_local_interface != 0 && my_addr != to_local_interface->ip) {
		to_local_interface = to_local_interface->next;
	}

	if (to_local_interface != 0) {
		printf("packet sent to local addr\n");
		if (my_ip->ip_p == ip_protocol_tcp || my_ip->ip_p == ip_protocol_tcp) {
			/* TCP/UDP payload */
			send_icmp_pkt(sr, buf, icmp_unreachable, icmp_port);
			printf("ICMP port unreachable\n");
			return; 
		}
		else if (my_ip->ip_p == ip_protocol_icmp) {
			sr_icmp_hdr_t *icmp = (sr_icmp_hdr_t*)(buf + sizeof(sr_ip_hdr_t));
			if (icmp->icmp_type == icmp_echo_reply) {
				send_icmp_pkt(sr, buf, icmp_echo_reply, 0);
				printf("ICMP echo reply\n");
				return;
			}
		}
	}
	else {
		/*check routing table for longest prefix match to get next hop IP/interface*/
		printf("checking routing table\n");
		struct in_addr in_ip;
		in_ip.s_addr = my_ip->ip_dst;
		struct sr_rt* nxt_hp = sr_rt_search(sr, in_ip);
		if (nxt_hp == 0) {
			printf("next hop not found\n");
			/* send ICMP net unreachable */
			send_icmp_pkt(sr, buf, icmp_unreachable, icmp_dest_net);
			return; 
		}
		else {
			printf("found next hop\n");
			struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, (uint32_t)nxt_hp->dest.s_addr);
			if(entry!=NULL){
				/* TODO CHANGE DATA TO BE CORRECT */
				sr_send_packet(sr , buf , len , iface);
				sr_arpreq_destroy(&sr->cache, entry);
			}
			else{
				struct sr_arpreq *request = sr_arpcache_queuereq(&sr->cache, entry->ip,buf,len,nxt_hp->interface);
				handle_arpreq(sr,request,&sr->cache);
			}
			return;
		}
	}
}


int send_icmp_pkt(struct sr_instance* sr, uint8_t* buf, uint8_t type, uint8_t code) {
    printf("sending icmp packet\n");
	uint8_t* block = 0;
	switch(type) {
		case icmp_unreachable:
			block = malloc(sizeof(sr_icmp_t3_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t));
			sr_icmp_t3_hdr_t* icmp_error = (sr_icmp_t3_hdr_t*)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			icmp_error->icmp_type = type;
			icmp_error->icmp_code = code;
			icmp_error->icmp_sum  = 0;
			icmp_error->unused = 0;
			icmp_error->next_mtu = 0;
			memcpy(icmp_error->data, buf, ICMP_DATA_SIZE);
			icmp_error->icmp_sum = cksum(icmp_error, sizeof(sr_icmp_t3_hdr_t));
			break;
		case icmp_echo_reply:
			block = malloc(sizeof(sr_icmp_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t));
			sr_icmp_hdr_t* icmp_echo = (sr_icmp_hdr_t*)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			icmp_echo->icmp_type = type;
			icmp_echo->icmp_code = code;
			icmp_echo->icmp_sum  = 0;
			icmp_echo->icmp_sum = cksum(icmp_echo, sizeof(sr_icmp_hdr_t));
			break;
		case icmp_time_exceeded:
			block = malloc(sizeof(sr_icmp_t3_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t));
			sr_icmp_t3_hdr_t* icmp_timeout = (sr_icmp_t3_hdr_t*)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			icmp_timeout->icmp_type = type;
			icmp_timeout->icmp_code = code;
			icmp_timeout->icmp_sum  = 0;
			icmp_timeout->unused = 0;
			icmp_timeout->next_mtu = 0;
			memcpy(icmp_timeout->data, buf, ICMP_DATA_SIZE);
			icmp_timeout->icmp_sum = cksum(icmp_timeout, sizeof(sr_icmp_t3_hdr_t));
			break;
		default:
			/* shouldn't arrive here in our system setup */
			break;
	}
	/* populate IP header */
	sr_ip_hdr_t* ip_icmp_error = (sr_ip_hdr_t*)(block+sizeof(sr_ethernet_hdr_t));
	ip_icmp_error->ip_hl = sizeof(sr_ip_hdr_t);
	ip_icmp_error->ip_v  = 4;
	ip_icmp_error->ip_tos = 0x0000;
	if(type == icmp_unreachable || type == icmp_time_exceeded) {
		ip_icmp_error->ip_len = sizeof(sr_icmp_t3_hdr_t)+sizeof(sr_ip_hdr_t);
	} else {
		ip_icmp_error->ip_len = sizeof(sr_icmp_hdr_t)+sizeof(sr_ip_hdr_t);
	}
	ip_icmp_error->ip_id = ((sr_ip_hdr_t*)(buf))->ip_id;
	ip_icmp_error->ip_off = htons(IP_DF);
	ip_icmp_error->ip_ttl = IP_TTL; 
	ip_icmp_error->ip_p = ip_protocol_icmp;
	ip_icmp_error->ip_dst = ((sr_ip_hdr_t*)(buf))->ip_src;
	struct in_addr i;
	i.s_addr = ip_icmp_error->ip_dst;
	char* iface = (sr_rt_search(sr, i))->interface;
	ip_icmp_error->ip_src =  sr_get_interface(sr, iface)->ip;
	ip_icmp_error->ip_sum = 0;
	ip_icmp_error->ip_sum = cksum(ip_icmp_error, sizeof(sr_ip_hdr_t));
	/* add to arp req queue */
	sr_arpcache_queuereq(&sr->cache, ip_icmp_error->ip_dst, block, sizeof(block), iface);
	return 0;
}
