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

int ethernet_hdr_size = sizeof(sr_ethernet_hdr_t);
int ip_hdr_size = sizeof(sr_ip_hdr_t);
int icmp_t11_hdr_size = sizeof(sr_icmp_t11_hdr_t);
int icmp_t3_hdr_size = sizeof(sr_icmp_t3_hdr_t);

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
  /* print_hdrs(packet, len); */
  uint16_t my_ethertype = ethertype(packet);
	switch (my_ethertype) {


		case ethertype_ip:
			printf("The packet is a data packet\n");
			/*sr_handle_ip(sr, packet + ethernet_hdr_size, len - ethernet_hdr_size, interface);*/
			sr_handle_ip(sr, packet, len, interface);
			return;

		case ethertype_arp:
			choose_arp(sr, packet, len, interface);
			return;

	}

}/* end sr_ForwardPacket */

/* Choose ARP */
void choose_arp(struct sr_instance* sr, uint8_t * packet, unsigned int len, const char* iface){
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet+ sizeof(sr_ethernet_hdr_t));
	switch (ntohs(arp_hdr->ar_op)) {
	case arp_op_request:
		printf("The packet is an ARP request\n");
		handle_arprequest(sr, packet, len, iface);
		return;
	case arp_op_reply:
		printf("The packet is an ARP reply\n");
		handle_arpreply(sr, packet);
		return;
	}
}

/* Handle ARP request */
void handle_arprequest(struct sr_instance* sr, uint8_t * packet, unsigned int len, const char* iface){
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet+ sizeof(sr_ethernet_hdr_t));
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
	struct sr_if* interface = sr_get_interface(sr, iface);
	if(interface->ip == arp_hdr->ar_tip){
		uint8_t *buf = malloc(len*sizeof(uint8_t));
		sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
		sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(buf+sizeof(sr_ethernet_hdr_t));
		memcpy(ehdr->ether_dhost, arp_hdr->ar_sha, 6);
		memcpy(ehdr->ether_shost, interface->addr, 6);
		ehdr->ether_type = eth_hdr->ether_type;
		arphdr->ar_op = htons(arp_op_reply);
		arphdr->ar_hrd = arp_hdr->ar_hrd;
		arphdr->ar_pro = arp_hdr->ar_pro;
		arphdr->ar_hln = arp_hdr->ar_hln;
		arphdr->ar_pln = arp_hdr->ar_pln;
		memcpy(arphdr->ar_sha, interface->addr, 6);
		arphdr->ar_sip = interface->ip;
		memcpy(arphdr->ar_tha, arp_hdr->ar_sha, 6);
		arphdr->ar_tip = arp_hdr->ar_sip;
		printf("Sending ARP reply\n");
		sr_send_packet(sr, buf, len, interface->name);
		free(buf);
	}
	return;
}

/* Handles sending out ARP requests at the correct time intervals */
int handle_arpreq(struct sr_instance *sr, struct sr_arpreq *request, struct sr_arpcache *cache){
	if(difftime(time(NULL), request->sent)>1.0){
		if(request->times_sent == 5){
			/*sr_icmp_dest_host_unreachable(sr, request->packets->buf, 1);*/
			/* send_icmp_pkt(sr, request->packets->buf, icmp_unreachable, icmp_dest_host); */
			sr_arpreq_destroy(cache,request);
			request = NULL;
			return 2;
		}
		else{
			send_arpreq(sr, request);
			request->sent = time(NULL);
			request->times_sent++;
			return 1;
		}
	}
	return 0;
}

/* Iterate through and send all packets of a request */
void send_reqpack(struct sr_arpreq *request, struct sr_instance* sr){
	printf("Sending request packets\n");
	struct sr_packet *current = NULL;
	if(request->packets != NULL){
		current = request->packets;
	}
	struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, request->ip);
	if(current!=NULL && entry != NULL){
		sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)(current->buf);
		struct sr_if* interface = sr_get_interface(sr, current->iface);
		memcpy(ehdr->ether_dhost, entry->mac, 6);
		memcpy(ehdr->ether_shost, interface->addr, 6);
		printf("PACKET SENT\n");
		sr_send_packet(sr, current->buf, current->len, interface->name);
	}
	struct sr_packet *next = NULL;
	if(current!=NULL && entry!= NULL && current->next!=NULL){
		next = current->next;
	}
	while(next!=NULL){
		current = next;
		next = current->next;
		sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)(current->buf);
		struct sr_if* interface = sr_get_interface(sr, current->iface);
		memcpy(ehdr->ether_dhost, entry->mac, 6);
		memcpy(ehdr->ether_shost, interface->addr, 6);
		printf("PACKET SENT\n");
		sr_send_packet(sr, current->buf, current->len, current->iface);
	}
	if(entry!=NULL){
		free(entry);
	}
}

/* Handle when an ARP reply is received */
void handle_arpreply(struct sr_instance* sr, uint8_t * packet){
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet+ sizeof(sr_ethernet_hdr_t));
    print_addr_eth(arp_hdr->ar_sha);
    print_addr_ip_int(ntohl(arp_hdr->ar_sip));
    struct sr_arpreq *request = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    struct sr_arpentry* entry = NULL;
    if(request!=NULL){
    	entry = sr_arpcache_lookup(&sr->cache, request->ip);
    }
	if(request != NULL && entry != NULL){
		printf("ARP found in cache\n");
	    send_reqpack(request, sr);
		sr_arpreq_destroy(&sr->cache,request);
	}
	else{
		printf("ARP not found in cache\n");
	}
}

/* Sends an ARP request */
void send_arpreq(struct sr_instance* sr, struct sr_arpreq *request){
	uint8_t *buf = malloc(42*sizeof(uint8_t));
	uint8_t ffff[6] = {255,255,255,255,255,255};
	uint8_t tstf[6] = {0,0,0,0,0,0};
	sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
	sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(buf+sizeof(sr_ethernet_hdr_t));
	struct sr_if* interface = sr_get_interface(sr, request->packets->iface);
	memcpy(ehdr->ether_dhost, ffff, 6);
	memcpy(ehdr->ether_shost, interface->addr, 6);
	ehdr->ether_type = htons(ethertype_arp);
	arphdr->ar_op = htons(arp_op_request);
	arphdr->ar_hrd = htons(1);
	arphdr->ar_pro = htons(2048);
	arphdr->ar_hln = 6;
	arphdr->ar_pln = 4;
	memcpy(arphdr->ar_sha, interface->addr, 6);
	arphdr->ar_sip = interface->ip;
	memcpy(arphdr->ar_tha, tstf, 6);
	arphdr->ar_tip = request->ip;
	printf("Sending ARP request\n");
	sr_send_packet(sr, buf, 42, interface->name);
	free(buf);
}

void sr_handle_ip(struct sr_instance* sr, uint8_t * packet, unsigned int len, const char* interface) {
  	if (len < ethernet_hdr_size + ip_hdr_size) {
  		return;
  	}
  	sr_ip_hdr_t *my_ip_hdr = (sr_ip_hdr_t*)(packet + ethernet_hdr_size);
  	uint32_t received_cksum = my_ip_hdr->ip_sum;
  	my_ip_hdr->ip_sum = 0;
  	uint32_t calculated_cksum = cksum(my_ip_hdr, my_ip_hdr->ip_hl * 4);
  	if (calculated_cksum != received_cksum) {
  		return;
  	}
  	my_ip_hdr->ip_sum = calculated_cksum;
  	struct sr_if *to_router_interface = sr_get_interface_by_ip(sr, my_ip_hdr->ip_dst);
  	if (to_router_interface) {
  		if (my_ip_hdr->ip_p == ip_protocol_icmp) {
  			sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(packet + ethernet_hdr_size + ip_hdr_size);
  			sr_icmp_echo_reply(sr, my_ip_hdr);
  		}
		else if (my_ip_hdr->ip_p == ip_protocol_udp || my_ip_hdr->ip_p == ip_protocol_tcp) {
			sr_icmp_port_unreachable(sr, my_ip_hdr, 3); 
  		}
 	}
	else {
  		if (my_ip_hdr->ip_ttl <= 1) {
  			sr_icmp_time_exceeded(sr, my_ip_hdr);
  			return;
  		}
  		my_ip_hdr->ip_ttl = my_ip_hdr->ip_ttl - 1;
	  	my_ip_hdr->ip_sum = 0;
	  	my_ip_hdr->ip_sum = cksum(my_ip_hdr, my_ip_hdr->ip_hl * 4);
		struct sr_rt *my_match = sr_longest_prefix_match(sr, my_ip_hdr->ip_dst);
		if (my_match) {
			struct sr_if* my_interface = sr_get_interface(sr, my_match->interface);
			sr_get_nexthop(sr, packet, len, my_match->gw.s_addr, my_interface);
		}
		else {
			sr_icmp_dest_net_unreachable(sr, my_ip_hdr, 0);
  		}
	}
}

void sr_icmp_echo_reply(struct sr_instance* sr, sr_ip_hdr_t* my_ip_hdr) {
	printf("ICMP echo reply\n");
	uint16_t iplen = ntohs(my_ip_hdr->ip_len);
	unsigned int len = ethernet_hdr_size + iplen;
	uint8_t* buf = (uint8_t*)malloc(len);	
	sr_ethernet_hdr_t* eth_hdr =(sr_ethernet_hdr_t*)(buf);
	eth_hdr->ether_type = htons(ethertype_ip);
	memset(eth_hdr->ether_shost, 0x00, 6);
	memset(eth_hdr->ether_dhost, 0x00, 6);

	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(buf + ethernet_hdr_size);
	memcpy(ip_hdr, my_ip_hdr, iplen);
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_dst = my_ip_hdr->ip_src;
	ip_hdr->ip_src = my_ip_hdr->ip_dst;
	ip_hdr->ip_ttl = 255;
	ip_hdr->ip_sum = cksum(buf + ethernet_hdr_size, ip_hdr_size);
	
	struct sr_rt *my_match = sr_longest_prefix_match(sr, ip_hdr->ip_dst);
	if (! my_match) {
		fprintf(stderr,"Destination net unreachable from the router\n");
		free(buf);
		return;
	}
	struct sr_if* interface = sr_get_interface(sr, my_match->interface);
		
	sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(buf + ethernet_hdr_size + ip_hdr_size);
	icmp_hdr->icmp_type = 0;
	icmp_hdr->icmp_code = 0;
	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = cksum((uint8_t*)icmp_hdr, iplen - ip_hdr_size);
													  	
	sr_get_nexthop(sr, buf, len, my_match->gw.s_addr, interface);
	free(buf);
}

void sr_icmp_dest_net_unreachable(struct sr_instance* sr, sr_ip_hdr_t* my_ip_hdr, uint8_t code) {
	printf("ICMP net unreachable\n");
	
	unsigned int len = ethernet_hdr_size + ip_hdr_size + icmp_t3_hdr_size;
	uint8_t* buf = (uint8_t*)malloc(len);
	
	sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)(buf);
	eth_hdr->ether_type = htons(ethertype_ip);
	memset(eth_hdr->ether_shost, 0x00, 6);
	memset(eth_hdr->ether_dhost, 0x00, 6);

	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(buf + ethernet_hdr_size);
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = my_ip_hdr->ip_tos;
	ip_hdr->ip_len = htons(len - ethernet_hdr_size);
	ip_hdr->ip_id = my_ip_hdr->ip_id;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_p = 1;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_dst = my_ip_hdr->ip_src;
	
	struct sr_rt *my_match = sr_longest_prefix_match(sr, ip_hdr->ip_dst);
	if (! my_match) {
		fprintf(stderr,"Destination net unreachable from the router\n");
		free(buf);
		return;
	}
	struct sr_if* interface = sr_get_interface(sr, my_match->interface);
	
	ip_hdr->ip_src = interface->ip;
	
	ip_hdr->ip_sum = cksum((uint8_t*)ip_hdr, ip_hdr_size);
	
	sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t*)((uint8_t*)ip_hdr + ip_hdr_size);
	icmp_hdr->icmp_type = 3;
	icmp_hdr->icmp_code = code;
	icmp_hdr->icmp_sum  = 0;
	memcpy(icmp_hdr->data, (uint8_t*)my_ip_hdr, ICMP_DATA_SIZE);
	icmp_hdr->icmp_sum = cksum((uint8_t*)icmp_hdr, len - ethernet_hdr_size - ip_hdr_size);
													  	
	sr_get_nexthop(sr, buf, len, my_match->gw.s_addr, interface);
	free(buf);
}

void sr_icmp_dest_host_unreachable(struct sr_instance* sr, sr_ip_hdr_t* my_ip_hdr, uint8_t code) {
	printf("ICMP host unreachable\n");
	
	unsigned int len = ethernet_hdr_size + ip_hdr_size + icmp_t3_hdr_size;
	uint8_t* buf = (uint8_t*)malloc(len);
	
	sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)(buf);
	eth_hdr->ether_type = htons(ethertype_ip);
	memset(eth_hdr->ether_shost, 0x00, 6);
	memset(eth_hdr->ether_dhost, 0x00, 6);

	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(buf + ethernet_hdr_size);
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = my_ip_hdr->ip_tos;
	ip_hdr->ip_len = htons(len - ethernet_hdr_size);
	ip_hdr->ip_id = my_ip_hdr->ip_id;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_p = 1;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_dst = my_ip_hdr->ip_src;
	
	struct sr_rt *my_match = sr_longest_prefix_match(sr, ip_hdr->ip_dst);
	if (! my_match) {
		fprintf(stderr,"Destination net unreachable from the router\n");
		free(buf);
		return;
	}
	struct sr_if* interface = sr_get_interface(sr, my_match->interface);
	
	ip_hdr->ip_src = my_ip_hdr->ip_dst;
	
	ip_hdr->ip_sum = cksum((uint8_t*)ip_hdr, ip_hdr_size);
	
	sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t*)((uint8_t*)ip_hdr + ip_hdr_size);
	icmp_hdr->icmp_type = 3;
	icmp_hdr->icmp_code = code;
	icmp_hdr->icmp_sum  = 0;
	memcpy(icmp_hdr->data, (uint8_t*)my_ip_hdr, ICMP_DATA_SIZE);
	icmp_hdr->icmp_sum = cksum((uint8_t*)icmp_hdr, len - ethernet_hdr_size - ip_hdr_size);
													  	
	sr_get_nexthop(sr, buf, len, my_match->gw.s_addr, interface);
	free(buf);
}

void sr_icmp_port_unreachable(struct sr_instance* sr, sr_ip_hdr_t* my_ip_hdr, uint8_t code) {
	printf("ICMP port unreachable\n");
	
	unsigned int len = ethernet_hdr_size + ip_hdr_size + icmp_t3_hdr_size;
	uint8_t* buf = (uint8_t*)malloc(len);
	
	sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)(buf);
	eth_hdr->ether_type = htons(ethertype_ip);
	memset(eth_hdr->ether_shost, 0x00, 6);
	memset(eth_hdr->ether_dhost, 0x00, 6);

	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(buf + ethernet_hdr_size);
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = my_ip_hdr->ip_tos;
	ip_hdr->ip_len = htons(len - ethernet_hdr_size);
	ip_hdr->ip_id = my_ip_hdr->ip_id;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_p = 1;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_dst = my_ip_hdr->ip_src;
	
	struct sr_rt *my_match = sr_longest_prefix_match(sr, ip_hdr->ip_dst);
	if (! my_match) {
		fprintf(stderr,"Destination net unreachable from the router\n");
		free(buf);
		return;
	}
	struct sr_if* interface = sr_get_interface(sr, my_match->interface);
	
	if (code == 3) ip_hdr->ip_src = my_ip_hdr->ip_dst;
	else ip_hdr->ip_src = interface->ip;
	
	ip_hdr->ip_sum = cksum((uint8_t*)ip_hdr, ip_hdr_size);
	
	sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t*)((uint8_t*)ip_hdr + ip_hdr_size);
	icmp_hdr->icmp_type = 3;
	icmp_hdr->icmp_code = code;
	icmp_hdr->icmp_sum  = 0;
	memcpy(icmp_hdr->data, (uint8_t*)my_ip_hdr, ICMP_DATA_SIZE);
	icmp_hdr->icmp_sum = cksum((uint8_t*)icmp_hdr, len - ethernet_hdr_size - ip_hdr_size);
													  	
	sr_get_nexthop(sr, buf, len, my_match->gw.s_addr, interface);
	free(buf);
}

void sr_icmp_time_exceeded(struct sr_instance* sr, sr_ip_hdr_t* my_ip_hdr){
	printf("ICMP TLE\n");
	unsigned int len = ethernet_hdr_size + ip_hdr_size + icmp_t11_hdr_size;
	uint8_t* buf = (uint8_t*)malloc(len);	
	sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)(buf);
	eth_hdr->ether_type = htons(ethertype_ip);
	memset(eth_hdr->ether_shost, 0x00, 6);
	memset(eth_hdr->ether_dhost, 0x00, 6);

	sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t*)(buf + ethernet_hdr_size);
	new_ip_hdr->ip_hl = 5;
	new_ip_hdr->ip_v = 4;
	new_ip_hdr->ip_tos = my_ip_hdr->ip_tos;
	new_ip_hdr->ip_len = htons(len - ethernet_hdr_size);
	new_ip_hdr->ip_id = my_ip_hdr->ip_id;
	new_ip_hdr->ip_off = 0;
	new_ip_hdr->ip_ttl = 64;
	new_ip_hdr->ip_p = 1;
	new_ip_hdr->ip_sum = 0;
	new_ip_hdr->ip_dst = my_ip_hdr->ip_src;	
	struct sr_rt *my_match = sr_longest_prefix_match(sr, new_ip_hdr->ip_dst);
	if (! my_match) {
		fprintf(stderr,"Destination net unreachable from the router\n");
		free(buf);
		return;
	}
	struct sr_if* interface = sr_get_interface(sr, my_match->interface);
	
	new_ip_hdr->ip_src = interface->ip;
	new_ip_hdr->ip_sum = cksum(buf + ethernet_hdr_size, ip_hdr_size);
	
	sr_icmp_t11_hdr_t *icmp_hdr = (sr_icmp_t11_hdr_t*)(buf + ethernet_hdr_size + ip_hdr_size);
	icmp_hdr->icmp_type = 11;
	icmp_hdr->icmp_code = 0;
	icmp_hdr->icmp_sum  = 0;
	memcpy(icmp_hdr->data, (uint8_t*)my_ip_hdr, ICMP_DATA_SIZE);
	icmp_hdr->icmp_sum = cksum((uint8_t*)icmp_hdr, len - ethernet_hdr_size - ip_hdr_size);
													  	
	sr_get_nexthop(sr ,buf, len, my_match->gw.s_addr, interface);
	free(buf);
}

void sr_get_nexthop(struct sr_instance* sr, uint8_t* packet, unsigned int len, uint32_t s_addr, struct sr_if* interface) {
	assert(sr);
	assert(packet);
	assert(interface);
	
	struct sr_arpentry* my_arp = sr_arpcache_lookup(&sr->cache, s_addr);
	if (my_arp) {
		sr_ethernet_hdr_t* my_eth_hdr = (sr_ethernet_hdr_t*)(packet);
		memcpy(my_eth_hdr->ether_dhost, my_arp->mac, 6);
		memcpy(my_eth_hdr->ether_shost, interface->addr, 6);
		printf("FIRST TRY\n");
		sr_send_packet(sr, packet, len, interface->name);
		/* Free entry? */
	}
	else {
		struct sr_arpreq *request = sr_arpcache_queuereq(&sr->cache, s_addr, packet, len, interface->name);
		handle_arpreq(sr,request,&sr->cache);
	}
}

