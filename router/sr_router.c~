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

void sr_handle_ip(struct sr_instance* sr, uint8_t * packet, unsigned int len, const char* iface) {
	int ethernet_hdr_size = sizeof(sr_ethernet_hdr_t);
	int ip_hdr_size = sizeof(sr_ip_hdr_t);
	int  min_ip_len = ethernet_hdr_size + ip_hdr_size;
  	if (len < min_ip_len) {
  		return;
  	}
  	sr_ip_hdr_t *my_ip_hdr = (sr_ip_hdr_t*)(packet + ethernet_hdr_size);
  	/*if (iphdr->ip_v != 4 || iphdr->ip_hl < 5){
  		fprintf(stderr,"packet version/hl wrong\n");
  		return;
  	}*/
  	uint32_t received_cksum = my_ip_hdr->ip_sum;
  	my_ip_hdr->ip_sum = 0;
  	uint32_t calculated_cksum = cksum(my_ip_hdr,my_ip_hdr->ip_hl*4);
  	if (calculated_cksum != received_cksum) {
  		fprintf(stderr,"packet checksum WRONG\n");
  		return;
  	}
  	my_ip_hdr->ip_sum = calculated_cksum;
  	printf("ip checksum OK\n");
  	struct sr_if *to_interface = sr_get_interface_by_ip(sr,my_ip_hdr->ip_dst);
  	if (to_interface) {
  		printf("IP for router\n");
  		if (my_ip_hdr->ip_p == 1) {
  			printf("it's an ICMP\n");
  			sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(packet + ethernet_hdr_size + ip_hdr_size);
  			if (icmp_hdr->icmp_type != 8 || icmp_hdr->icmp_code != 0) {
  				printf("not an echo request\n");
  				return;
  			}
  			uint32_t icmp_cksum = icmp_hdr->icmp_sum;
  			icmp_hdr->icmp_sum = 0;
  			if (icmp_cksum != cksum((uint8_t*)icmp_hdr, ntohs(my_ip_hdr->ip_len) - ip_hdr_size)) {
  				fprintf(stderr,"icmp cksum wrong \n");
  				return;
  			}
  			sr_icmp_echo_reply(sr, my_ip_hdr);
  		}
		else {
  			sr_icmp_dest_unr(sr, my_ip_hdr, 3);
  		}
  	}
	else{
  		printf("foward it\n");
  		printf("TTL = %d\n",my_ip_hdr->ip_ttl);
  		if (my_ip_hdr->ip_ttl == 1) {
  			printf("TTL = 0\n");
  			sr_icmp_TLE(sr, my_ip_hdr);
  			return;
  		}
  		my_ip_hdr->ip_ttl = my_ip_hdr->ip_ttl - 1;
	  	my_ip_hdr->ip_sum = 0;
	  	my_ip_hdr->ip_sum = cksum(my_ip_hdr,my_ip_hdr->ip_hl*4);
		struct sr_rt *tb = sr_LPM(sr,my_ip_hdr->ip_dst);
		if (!tb) {
			printf("no match in LPM,net unreachable\n");
			sr_icmp_dest_unr(sr,my_ip_hdr,0);
		}
		else {
			struct sr_if* interface = sr_get_interface(sr,tb->interface);
			sr_nexthop_ip_iface(sr,packet,len,tb->gw.s_addr,interface);
  		}
	}
}

void sr_icmp_TLE(struct sr_instance* sr, sr_ip_hdr_t* siphdr){
	printf("ICMP TLE\n");
	unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
	uint8_t* buf = (uint8_t*)malloc(len);	
	sr_ethernet_hdr_t* eth_hdr =(sr_ethernet_hdr_t*)(buf);
	eth_hdr->ether_type = htons(ethertype_ip);
	memset(eth_hdr->ether_shost,0x00,6);
	memset(eth_hdr->ether_dhost,0x00,6);

	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = siphdr->ip_tos;
	ip_hdr->ip_len = htons(len-sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_id = siphdr->ip_id;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_p = 1;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_dst = siphdr->ip_src;	
	struct sr_rt *tb = sr_LPM(sr, ip_hdr->ip_dst);
	if (!tb) {
		fprintf(stderr,"Destination net unreachable from the router\n");
		free(buf);
		return;
	}
	struct sr_if* interface = sr_get_interface(sr,tb->interface);
	
	ip_hdr->ip_src = interface->ip;
	ip_hdr->ip_sum = cksum(buf+sizeof(sr_ethernet_hdr_t),sizeof(sr_ip_hdr_t));
	
	sr_icmp_t11_hdr_t *icmp_hdr = (sr_icmp_t11_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
	icmp_hdr->icmp_type = 11;
	icmp_hdr->icmp_code = 0;
	icmp_hdr->icmp_sum  = 0;
	memcpy(icmp_hdr->data, (uint8_t*)siphdr, ICMP_DATA_SIZE);
	icmp_hdr->icmp_sum = cksum((uint8_t*)icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
													  	
	sr_nexthop_ip_iface(sr ,buf, len, tb->gw.s_addr, interface);
	free(buf);
}

void sr_icmp_echo_reply(struct sr_instance* sr, sr_ip_hdr_t* siphdr) {
	printf("ICMP echo reply\n");
	uint16_t iplen = ntohs(siphdr->ip_len);
	unsigned int len = sizeof(sr_ethernet_hdr_t) + iplen;
	uint8_t* buf = (uint8_t*)malloc(len);	
	sr_ethernet_hdr_t* eth_hdr =(sr_ethernet_hdr_t*)(buf);
	eth_hdr->ether_type = htons(ethertype_ip);
	memset(eth_hdr->ether_shost,0x00,6);
	memset(eth_hdr->ether_dhost,0x00,6);

	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));
	memcpy(ip_hdr, siphdr, iplen);
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_dst = siphdr->ip_src;
	ip_hdr->ip_src = siphdr->ip_dst;
	ip_hdr->ip_sum = cksum(buf + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
	
	struct sr_rt *tb = sr_LPM(sr, ip_hdr->ip_dst);
	if (!tb) {
		fprintf(stderr,"Destination net unreachable from the router\n");
		free(buf);
		return;
	}
	struct sr_if* interface = sr_get_interface(sr, tb->interface);
		
	sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	icmp_hdr->icmp_type = 0;
	icmp_hdr->icmp_code = 0;
	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = cksum((uint8_t*)icmp_hdr, iplen-sizeof(sr_ip_hdr_t));
													  	
	sr_nexthop_ip_iface(sr, buf, len, tb->gw.s_addr, interface);
	free(buf);
}

void sr_icmp_dest_unr(struct sr_instance* sr, sr_ip_hdr_t* siphdr, uint8_t code){
	if (code == 0) printf("ICMP net unreachable\n");
	else if(code == 1) printf("ICMP host unreachable\n");
	else printf("ICMP port unreachable\n");
	
	unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	uint8_t* buf = (uint8_t*)malloc(len);
	
	sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)(buf);
	eth_hdr->ether_type = htons(ethertype_ip);
	memset(eth_hdr->ether_shost,0x00,6);
	memset(eth_hdr->ether_dhost,0x00,6);

	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = siphdr->ip_tos;
	ip_hdr->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_id = siphdr->ip_id;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_p = 1;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_dst = siphdr->ip_src;
	
	struct sr_rt *tb = sr_LPM(sr,ip_hdr->ip_dst);
	if (!tb) {
		fprintf(stderr,"Destination net unreachable from the router\n");
		free(buf);
		return;
	}
	struct sr_if* interface = sr_get_interface(sr,tb->interface);
	
	if (code == 3) ip_hdr->ip_src = siphdr->ip_dst;
	else ip_hdr->ip_src = interface->ip;
	
	ip_hdr->ip_sum = cksum((uint8_t*)ip_hdr, sizeof(sr_ip_hdr_t));
	
	sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));
	icmp_hdr->icmp_type = 3;
	icmp_hdr->icmp_code = code;
	icmp_hdr->icmp_sum  = 0;
	memcpy(icmp_hdr->data, (uint8_t*)siphdr, ICMP_DATA_SIZE);
	icmp_hdr->icmp_sum = cksum((uint8_t*)icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
													  	
	sr_nexthop_ip_iface(sr, buf, len, tb->gw.s_addr, interface);
	free(buf);
}



void sr_nexthop_ip_iface(struct sr_instance* sr, uint8_t* packet, unsigned int len, uint32_t tip, struct sr_if* interface) {
	assert(sr);
	assert(packet);
	assert(interface);
	
	struct sr_arpentry* arp = sr_arpcache_lookup(&sr->cache, tip);
	if (!arp) {
		printf("arp entry not found,try request");
		sr_arpcache_queuereq(&sr->cache, tip, packet, len, interface->name);
	}
	else {
		sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)(packet);
		memcpy(eth_hdr->ether_dhost, arp->mac, 6);
		memcpy(eth_hdr->ether_shost, interface->addr, 6);
		sr_send_packet(sr, packet, len, interface->name);
		free(arp);
	}
}

