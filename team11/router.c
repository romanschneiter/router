/*
     This file (was) part of GNUnet.
     Copyright (C) 2018 Christian Grothoff

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file router.c
 * @brief IPv4 router
 * @author Christian Grothoff
 */
#include "glab.h"
#include <stdbool.h>
#include <string.h>
#include <math.h>


/* see http://www.iana.org/assignments/ethernet-numbers */
#ifndef ETH_P_IPV4
/**
 * Number for IPv4
 */
#define ETH_P_IPV4 0x0800
#endif

#ifndef ETH_P_ARP
/**
 * Number for ARP
 */
#define ETH_P_ARP 0x0806
#endif

//
#define MAX_ENTRIES 16


/**
 * gcc 4.x-ism to pack structures (to be used before structs);
 * Using this still causes structs to be unaligned on the stack on Sparc
 * (See #670578 from Debian).
 */
_Pragma("pack(push)") _Pragma("pack(1)")

struct EthernetHeader
{
  struct MacAddress dst;
  struct MacAddress src;

  /**
   * See ETH_P-values.
   */
  uint16_t tag;
};


/**
 * ARP header for Ethernet-IPv4.
 */
struct ArpHeaderEthernetIPv4
{
  /**
   * Must be #ARP_HTYPE_ETHERNET.
   */
  uint16_t htype;

  /**
   * Protocol type, must be #ARP_PTYPE_IPV4
   */
  uint16_t ptype;

  /**
   * HLEN.  Must be #MAC_ADDR_SIZE.
   */
  uint8_t hlen;

  /**
   * PLEN.  Must be sizeof (struct in_addr) (aka 4).
   */
  uint8_t plen;

  /**
   * Type of the operation.
   */
  uint16_t oper;

  /**
   * HW address of sender. We only support Ethernet.
   */
  struct MacAddress sender_ha;

  /**
   * Layer3-address of sender. We only support IPv4.
   */
  struct in_addr sender_pa;

  /**
   * HW address of target. We only support Ethernet.
   */
  struct MacAddress target_ha;

  /**
   * Layer3-address of target. We only support IPv4.
   */
  struct in_addr target_pa;
};


/* some systems use one underscore only, and mingw uses no underscore... */
#ifndef __BYTE_ORDER
#ifdef _BYTE_ORDER
#define __BYTE_ORDER _BYTE_ORDER
#else
#ifdef BYTE_ORDER
#define __BYTE_ORDER BYTE_ORDER
#endif
#endif
#endif
#ifndef __BIG_ENDIAN
#ifdef _BIG_ENDIAN
#define __BIG_ENDIAN _BIG_ENDIAN
#else
#ifdef BIG_ENDIAN
#define __BIG_ENDIAN BIG_ENDIAN
#endif
#endif
#endif
#ifndef __LITTLE_ENDIAN
#ifdef _LITTLE_ENDIAN
#define __LITTLE_ENDIAN _LITTLE_ENDIAN
#else
#ifdef LITTLE_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#endif
#endif
#endif


#define IP_FLAGS_RESERVED 1
#define IP_FLAGS_DO_NOT_FRAGMENT 2
#define IP_FLAGS_MORE_FRAGMENTS 4
#define IP_FLAGS 7

#define IP_FRAGMENT_MULTIPLE 8

/**
 * Standard IPv4 header.
 */
struct IPv4Header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
  unsigned int header_length : 4;
  unsigned int version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
  unsigned int version : 4;
  unsigned int header_length : 4;
#else
  #error byteorder undefined
#endif
  uint8_t diff_serv;

  /**
   * Length of the packet, including this header.
   */
  uint16_t total_length;

  /**
   * Unique random ID for matching up fragments.
   */
  uint16_t identification;

  /**
   * Fragmentation flags and fragmentation offset.
   */
  uint16_t fragmentation_info;

  /**
   * How many more hops can this packet be forwarded?
   */
  uint8_t ttl;

  /**
   * L4-protocol, for example, IPPROTO_UDP or IPPROTO_TCP.
   */
  uint8_t protocol;

  /**
   * Checksum.
   */
  uint16_t checksum;

  /**
   * Origin of the packet.
   */
  struct in_addr source_address;

  /**
   * Destination of the packet.
   */
  struct in_addr destination_address;
};


#define ICMPTYPE_DESTINATION_UNREACHABLE 3
#define ICMPTYPE_TIME_EXCEEDED 11

#define ICMPCODE_NETWORK_UNREACHABLE 0
#define ICMPCODE_HOST_UNREACHABLE 1
#define ICMPCODE_FRAGMENTATION_REQUIRED 4

/**
 * ICMP header.
 */
struct IcmpHeader
{
  uint8_t type;
  uint8_t code;
  uint16_t crc;

  union
  {
    /**
     * Payload for #ICMPTYPE_DESTINATION_UNREACHABLE (RFC 1191)
     */
    struct ih_pmtu
    {
      uint16_t empty;
      uint16_t next_hop_mtu;
    } destination_unreachable;

    /**
     * Unused bytes for #ICMPTYPE_TIME_EXCEEDED.
     */
    uint32_t time_exceeded_unused;

  } quench;

  /* followed by original IP header + first 8 bytes of original IP datagram
     (at least for the two ICMP message types we care about here) */

};
_Pragma("pack(pop)")


/**
 * Per-interface context.
 */
struct Interface
{
  /**
   * MAC of interface.
   */
  struct MacAddress mac;

  /**
   * IPv4 address of interface (we only support one IP per interface!)
   */
  struct in_addr ip;

  /**
   * IPv4 netmask of interface.
   */
  struct in_addr netmask;

  /**
   * Name of the interface.
   */
  char *name;

  /**
   * Number of this interface.
   */
  uint16_t ifc_num;

  /**
   * MTU to enforce for this interface.
   */
  uint16_t mtu;
};


/**
 * Number of available contexts.
 */
static unsigned int num_ifc;

/**
 * All the contexts.
 */
static struct Interface *gifc;

//---arp-table
struct Interface table[MAX_ENTRIES];
int tableIndex = 0;
struct MacAddress broadcastMac;
struct MacAddress nullMac;

struct in_addr nullInAddr;

//--routing-table
struct TableEntry{
    struct in_addr target_network;
    struct in_addr netmask;
    struct in_addr nextHop;
    struct Interface interface;
};

struct TableEntry routingTable[MAX_ENTRIES];
int routingTableIndex = 0;

//static struct Interface*
//find_interface (const char *name);


//---compare two mac-addresses
int macComp(const uint8_t mac1[], const uint8_t mac2[]){
  for(int i = 0; i<6; i++){
    if(mac1[i] != mac2[i]){
        return -1;
    }
  }
  return 0;
}

// Compares two ipv4 addresses
static int ipCmp (const struct in_addr *ip1, const struct in_addr *ip2) {
    return memcmp (ip1, ip2, sizeof (struct in_addr));
}

static int check_ip_network (struct in_addr ip1, struct in_addr ip2, struct in_addr netmask){
   return (ip2.s_addr & netmask.s_addr) == (ip1.s_addr & netmask.s_addr);
}

//prints the mac-address to std:err
static void print_mac (const struct MacAddress *mac) {
    print ("%02x:%02x:%02x:%02x:%02x:%02x",
    mac->mac[0], mac->mac[1],
    mac->mac[2], mac->mac[3],
    mac->mac[4], mac->mac[5]);
}

static void print_ip (const struct in_addr *ip){
   char buf[INET_ADDRSTRLEN];
   print ("%s", inet_ntop (AF_INET, ip, buf, sizeof (buf)));
}

//print_arp_Header
static void print_arpHeader (const struct ArpHeaderEthernetIPv4 *header){
   print("HType: %04x\n", header->htype);
   print("PType: %04x\n", header->ptype);
   print("HLength: %02x\n", header->hlen);
   print("PLength: %02x\n", header->plen);
   print("Operator: %04x\n", header->oper);
   print("Sender_ha: ");
   print_mac(&header->sender_ha);
   print("Sender_pa: ");
   print_ip(&header->sender_pa);
   print("Target_ha: ");
   print_mac(&header->target_ha);
   print("Target_pa: ");
   print_ip(&header->target_pa);
}

//print_arp_cache
static void print_arp_cache (void) {
   for (unsigned int i = 0; i < tableIndex; i++) {
      char buffer[INET_ADDRSTRLEN];
      struct in_addr *ip = &table[i].ip;
      char* name = table[i].name;
      print ("%s -> %02x:%02x:%02x:%02x:%02x:%02x (%4s)\n",
            inet_ntop (AF_INET,
            ip,
            buffer,
            sizeof (buffer)),
	        table[i].mac.mac[0],
	        table[i].mac.mac[1],
	        table[i].mac.mac[2],
	        table[i].mac.mac[3],
	        table[i].mac.mac[4],
	        table[i].mac.mac[5],
	        &name
	        );
   }
}

//Shift 8 Bits
static uint16_t shift_bytes(uint16_t n) {
  return ((n >> 8) | (n << 8));
}
//--

/**
 * Forward @a frame to interface @a dst.
 *
 * @param dst target interface to send the frame out on
 * @param frame the frame to forward
 * @param frame_size number of bytes in @a frame
 */
static void forward_to (struct Interface *dst, const void *frame, size_t frame_size) {
  char iob[frame_size + sizeof (struct GLAB_MessageHeader)];
  struct GLAB_MessageHeader hdr;

  if (frame_size > dst->mtu)
    abort ();
  hdr.size = htons (sizeof (iob));
  hdr.type = htons (dst->ifc_num);
  memcpy (iob,
          &hdr,
          sizeof (hdr));
  memcpy (&iob[sizeof (hdr)],
          frame,
          frame_size);
  write_all (STDOUT_FILENO,
             iob,
             sizeof (iob));
}


/**
 * Create Ethernet frame and forward it via @a ifc to @a target_ha.
 * Create Ethernet frame and forward it via @a ifc to @a target_ha.
 *
 * @param ifc interface to send frame out on
 * @param target destination MAC
 * @param tag Ethernet tag to use
 * @param frame_payload payload to use in frame
 * @param frame_payload_size number of bytes in @a frame_payload
 */
static void
forward_frame_payload_to (struct Interface *ifc,
                          const struct MacAddress *target_ha,
                          uint16_t tag,
                          const void *frame_payload,
                          size_t frame_payload_size)
{
  char frame[sizeof (struct EthernetHeader) + frame_payload_size];
  struct EthernetHeader eh;

  if (frame_payload_size + sizeof (struct EthernetHeader) > ifc->mtu)
    abort ();
  eh.dst = *target_ha;
  eh.src = ifc->mac;
  eh.tag = ntohs (tag);
  memcpy (frame,
          &eh,
          sizeof (eh));
  memcpy (&frame[sizeof (eh)],
          frame_payload,
          frame_payload_size);
  forward_to (ifc,
              frame,
              sizeof (frame));
}


/**
 * Route the @a ip packet with its @a payload.
 *
 * @param origin interface we received the packet from
 * @param ip IP header
 * @param payload IP packet payload
 * @param payload_size number of bytes in @a payload
 */
static void route (struct Interface *origin, const struct IPv4Header *ip, const void *payload, size_t payload_size, struct EthernetHeader eh){
  struct MacAddress target_mac;
  bool routeKnown = false;
  struct Interface arpTableInterface;
  for (int i = 0; i < tableIndex; i++){
       if (ipCmp (&table[i].ip, &ip->destination_address) == 0){
  			routeKnown = true;
  			arpTableInterface = table[i];
       }
  }

  struct TableEntry routingEntry;
  int bestNetmaskMatch = 0;
  int bestNetmaskMatchIndex = 0;
  bool foundTableEntry = false;

  for(int i = 0; i < routingTableIndex; i++){
    struct TableEntry temp;
    //vergleiche zieladresse mit Routing tabelle um zu prüfen ob target in in table gespeichert
    int maskDestination = ip->destination_address.s_addr & routingTable[i].netmask.s_addr;
    int maskNetwork = routingTable[i].target_network.s_addr & routingTable[i].netmask.s_addr;

    if (maskDestination == maskNetwork && &routingTable[i].interface != 0){
	    if (routingTable[i].netmask.s_addr >= bestNetmaskMatch){
		    bestNetmaskMatch = routingTable[i].netmask.s_addr;
		    bestNetmaskMatchIndex = i;
			foundTableEntry = true;
	    }
	}
  }
  //es wurde ein Eintrag gefunden
  routingEntry = routingTable[bestNetmaskMatchIndex];
  /* TODO: Eintrag not found*/

 if (!foundTableEntry){
	    struct IcmpHeader header;
            header.type = ICMPTYPE_DESTINATION_UNREACHABLE;
            header.code = ICMPCODE_NETWORK_UNREACHABLE;
            header.quench.time_exceeded_unused = 0;
            header.crc = GNUNET_CRYPTO_crc16_n(&header, sizeof(struct IcmpHeader));

            struct IPv4Header ipv4Header;
            memcpy (&ipv4Header, ip, sizeof(struct IPv4Header));
            ipv4Header.destination_address = ip->source_address;
            ipv4Header.source_address = origin->ip;
            ipv4Header.identification = 0;
            ipv4Header.diff_serv = 0;
            ipv4Header.ttl = 32;
            ipv4Header.protocol = IPPROTO_ICMP;
            ipv4Header.fragmentation_info = 0;
            ipv4Header.checksum = 0;
            ipv4Header.checksum = GNUNET_CRYPTO_crc16_n (&ipv4Header, sizeof(struct IPv4Header));

            char send [sizeof(struct IPv4Header) + sizeof(struct IPv4Header) + sizeof(struct IcmpHeader) + 8];

            memcpy (&send, &ipv4Header, sizeof(struct IPv4Header));
            memcpy (&send[sizeof(struct IPv4Header)], &header, sizeof(struct IcmpHeader));
            memcpy (&send[sizeof(struct IPv4Header) + sizeof(struct IcmpHeader)], ip, sizeof(struct IPv4Header));
            memcpy (&send[sizeof(struct IPv4Header) + sizeof(struct IcmpHeader) + sizeof(struct IPv4Header)], payload, 8);

            forward_frame_payload_to (origin, &eh.src, 0x0800, &send, 8 + sizeof(struct IPv4Header) + sizeof(struct IPv4Header) + sizeof(struct IcmpHeader));
            return;
	    }
	   // FOUND ROUTER ENTRY
	   struct IPv4Header newHeader;

	   memcpy (&newHeader, ip, sizeof (struct IPv4Header));
	   newHeader.ttl = newHeader.ttl - 1;

	   // check ttl
	   if (newHeader.ttl < 1){
		 return;
	   }
	   bool RemainingTTLhopNeeded = true;
           for (int i = 0; i < routingTableIndex; i++){
		   if (newHeader.destination_address.s_addr == 0){
			   RemainingTTLhopNeeded = false;
		   }
	   }
//____________________________________________________
  target_mac = arpTableInterface.mac;
//_________________________
	   if (RemainingTTLhopNeeded){
		for (int i = 0; i < tableIndex; i++){
			if (ipCmp (&table[i].ip, &routingEntry.nextHop) == 0){
				target_mac = table[i].mac;
			}
		}
	   } else {
	   }
//____________________________
  //If target-mac Null do arp
  if ( &target_mac == NULL){
	print("a\n");

    //Struktur Arp-Header
	struct EthernetHeader arpEh;

	arpEh.dst = broadcastMac;
	arpEh.src = routingEntry.interface.mac;
	arpEh.tag = htons(2054);

	struct ArpHeaderEthernetIPv4 arpHeader;
	arpHeader.htype = htons(1);
	arpHeader.ptype = htons(0x800);
	arpHeader.hlen = 6;
	arpHeader.plen = 4;
	arpHeader.oper = htons(1);
	arpHeader.sender_ha = routingEntry.interface.mac;
	arpHeader.sender_pa = routingEntry.interface.ip;
	arpHeader.target_ha = nullMac;
	arpHeader.target_pa = routingEntry.nextHop;

	void* ptr = malloc (sizeof (arpEh) + sizeof (arpHeader));
	memcpy (ptr, &arpEh, sizeof(arpEh));
	memcpy (ptr + sizeof(arpEh), &arpHeader, sizeof(arpHeader));
	forward_to (&routingEntry.interface, ptr, sizeof(ptr));
	free(ptr);
	return;
	}

//_________________________________________________________________________
// MTU Fragmentation Handling

  uint sizeHeadIPv4 =  sizeof(struct IPv4Header);
  uint sizeHeadIcmp = sizeof(struct IcmpHeader);
  uint sizeHeadEh = sizeof(struct EthernetHeader);

  // ok ___________________________________________________________________
  if(routingEntry.interface.mtu >= sizeHeadIPv4 + payload_size)
  {

    char send[sizeHeadIPv4 + payload_size];
    newHeader.checksum = 0;
    newHeader.checksum = GNUNET_CRYPTO_crc16_n(&newHeader, sizeHeadIPv4);
    memcpy (send, &newHeader, sizeHeadIPv4);
    memcpy (send + sizeHeadIPv4, payload, payload_size);
    	
    forward_frame_payload_to (
        &routingEntry.interface, 
        &target_mac, 
        0x0800, 
        send, 
        sizeHeadIPv4 + payload_size
    );
    return;
  }
  // not ok -> fragmentaion needed __________________________________________
  else{

    // check flags
    // fragment _____________________________________________________________
    if (ntohs (ip->fragmentation_info) >> 13 != 2){
      
      // beginn fragment
      bool hasNext  = (newHeader.fragmentation_info >> 13 == 1) 
                          ? true 
                          : false;
      bool islast = false;
      int sizeFragment, offset = 0;      
      uint16_t mtuIfc = routingEntry.interface.mtu - sizeHeadEh - sizeHeadIPv4;

      // check payload
      while (offset < payload_size)
      {
        islast  = (payload_size - offset) < mtuIfc 
              ? true 
              : false;

        sizeFragment  = (payload_size - offset) < mtuIfc 
                      ?  (payload_size - offset)
                      :  (mtuIfc - (mtuIfc % 8));

        struct IPv4Header fragmentHead;
        memcpy (&fragmentHead, &newHeader, sizeHeadIPv4);
        fragmentHead.checksum = 0;
        fragmentHead.total_length = htons(sizeFragment);
        fragmentHead.fragmentation_info = (islast && !hasNext)
                        ? htons(ntohs(newHeader.fragmentation_info) 
                        + (offset >> 3)) 
                        : htons((1 << 13) 
                        + ntohs(newHeader.fragmentation_info) 
                        + (offset >> 3));
        fragmentHead.checksum = GNUNET_CRYPTO_crc16_n (&fragmentHead, sizeHeadIPv4);
        
        char fragment[sizeFragment + sizeHeadIPv4];
        memcpy (&fragment, &fragmentHead, sizeHeadIPv4);
        memcpy (&fragment[sizeHeadIPv4], payload + offset, sizeFragment);
        
        offset += sizeFragment;

        forward_frame_payload_to (
            &routingEntry.interface, 
            &target_mac, 
            0x0800, 
            fragment, 
            sizeFragment
        );
      }
      return;
    } 
    // do not fragment ______________________________________________________
    else {

       struct IPv4Header ipv4Head;
      memcpy(&ipv4Head, ip, sizeHeadIPv4);
      ipv4Head.destination_address = ip->source_address;
      ipv4Head.source_address = origin->ip;
      ipv4Head.identification = 0;
      ipv4Head.diff_serv = 0;
      ipv4Head.ttl = 32;
      ipv4Head.protocol = IPPROTO_ICMP;
      ipv4Head.fragmentation_info = 0;
      ipv4Head.checksum = 0;
      ipv4Head.checksum = GNUNET_CRYPTO_crc16_n(&ipv4Head, sizeHeadIPv4);

      struct IcmpHeader head =  {
          .type = 3,
          .code = 4,
          .quench.destination_unreachable.empty = 0,
          .quench.destination_unreachable.next_hop_mtu 
              = htons(routingEntry.interface.mtu - sizeHeadEh),
          .crc = 0,
          .crc = GNUNET_CRYPTO_crc16_n(&head, sizeHeadIcmp)
      };

      char send[(sizeHeadIPv4 * 2) + sizeHeadIcmp + 8];
      memcpy (&send, &ipv4Head, sizeHeadIPv4);
      memcpy (&send[sizeHeadIPv4],&head,sizeHeadIcmp);
      memcpy (&send[sizeHeadIPv4 + sizeHeadIcmp],ip,sizeHeadIPv4);
      memcpy (&send[(sizeHeadIPv4 * 2) + sizeHeadIcmp], payload, 8);

      forward_frame_payload_to (
            origin, 
            &eh.src, 
            0x0800,
            &send, 
            (sizeHeadIPv4 * 2) + sizeHeadIcmp + 8
      ); 
      return;
    }
    //__________________________________________________________________
  } 
  // ___________________________________________________________________
}

/**
 * Process ARP (request or response!)
 *
 * @param ifc interface we received the ARP request from
 * @param eh ethernet header
 * @param ah ARP header
 */
static void handle_arp (struct Interface *ifc, const struct EthernetHeader *eh, const struct ArpHeaderEthernetIPv4 *ah){
  /* TODO: do work here */

  void *ptr = malloc(sizeof(struct EthernetHeader) + sizeof(struct ArpHeaderEthernetIPv4));

  if (macComp ((const uint8_t *) &eh->src,(const uint8_t *) &ah->sender_ha) != 0
        || eh->tag != 0x0608
		|| ah->htype != 0x100
		|| ah->ptype != 0x8
		|| ah->hlen != 0x6
		|| ah->plen != 0x4
		|| !(ah->oper == 0x100 || ah->oper == 0x200)){
      return;
  }

 if (ah->oper == ntohs(1)){
      struct EthernetHeader neh;
      neh.dst = ah->sender_ha;
      neh.src = ifc->mac;
      neh.tag = ntohs(0x0806);

      // build arphead
      struct ArpHeaderEthernetIPv4 newHeader = {
     .htype = htons(1),
	 .ptype = htons(0x0800),
	 .hlen = 6,
	 .plen = 4,
	 .oper = htons (1),
	 .sender_ha = {0},
	 .sender_pa = {0},
	 .target_ha = {0},
	 .target_pa = {0},
     };

        //sender is mac and ip
     memcpy (&newHeader.sender_ha, &ifc->mac.mac, 6);
     newHeader.sender_pa = ifc->ip;

        //target is the old source mac and ip
     memcpy (&newHeader.target_ha, &ah->sender_ha, 6);
     newHeader.target_pa = ah->sender_pa;

        //insert in frame
     memcpy (ptr, &neh, sizeof(struct EthernetHeader));
     memcpy (ptr + sizeof(struct EthernetHeader), &newHeader, sizeof(struct ArpHeaderEthernetIPv4));
     uint8_t size = sizeof (struct EthernetHeader) + sizeof (struct ArpHeaderEthernetIPv4);

	forward_to (ifc, ptr,size);
	}

  if (ah->oper == ntohs(2)) {

    bool contained = false;

    // Insert or update in the table
    for (int i = 0; i < MAX_ENTRIES; i++) {
      if (ipCmp(&table[i].ip, &ah->sender_pa) == 0) {
        // Update existing entry
        contained = true;
        table[i].mac = ah->sender_ha;
        table[i].netmask = ifc->netmask;
        memcpy(&table[i].name, ifc->name, sizeof(ifc->name));
        table[i].ifc_num = ifc->ifc_num;
        table[i].mtu = ifc->mtu;
        break;
      }
    }

    // Add to the table if not already contained
    if (!contained) {
      table[tableIndex].mac = ah->sender_ha;
      table[tableIndex].ip = ah->sender_pa;
      table[tableIndex].netmask = ifc->netmask;
      memcpy(&table[tableIndex].name, ifc->name, sizeof(ifc->name));
      table[tableIndex].ifc_num = ifc->ifc_num;
      table[tableIndex].mtu = ifc->mtu;

      tableIndex++;
      if (tableIndex >= MAX_ENTRIES) {
        tableIndex = 0;
      }
    }

    free(ptr);
  }
}

/**
 * Parse and process frame received on @a ifc.
 *
 * @param ifc interface we got the frame on
 * @param frame raw frame data
 * @param frame_size number of bytes in @a frame
 */
static void
parse_frame (struct Interface *ifc,
             const void *frame,
             size_t frame_size)
{
  struct EthernetHeader eh;
  const char *cframe = frame;

  if (frame_size < sizeof (eh))
  {
    fprintf (stderr,
             "Malformed frame\n");
    return;
  }
  memcpy (&eh,
          frame,
          sizeof (eh));
  switch (ntohs (eh.tag))
  {
  case ETH_P_IPV4:
    {
      struct IPv4Header ip;

      if (frame_size < sizeof (struct EthernetHeader) + sizeof (struct
                                                                IPv4Header))
      {
        fprintf (stderr,
                 "Malformed frame\n");
        return;
      }
      memcpy (&ip,
              &cframe[sizeof (struct EthernetHeader)],
              sizeof (struct IPv4Header));
      /* TODO: possibly do work here (ARP learning) */
      route (ifc, &ip, &cframe[sizeof (struct EthernetHeader) + sizeof (struct IPv4Header)],
            frame_size - sizeof (struct EthernetHeader) - sizeof (struct IPv4Header),eh);
      break;
    }
  case ETH_P_ARP:
    {
      struct ArpHeaderEthernetIPv4 ah;

      if (frame_size < sizeof (struct EthernetHeader) + sizeof (struct ArpHeaderEthernetIPv4)){
#if DEBUG
        fprintf (stderr, "Unsupported ARP frame\n");
#endif
        return;
      }
      memcpy (&ah, &cframe[sizeof (struct EthernetHeader)], sizeof (struct ArpHeaderEthernetIPv4));
      handle_arp (ifc, &eh, &ah);
      break;
    }
  default:
#if DEBUG
    fprintf (stderr, "Unsupported Ethernet tag %04X\n", ntohs (eh.tag));
#endif
    return;
  }
}


/**
 * Process frame received from @a interface.
 *
 * @param interface number of the interface on which we received @a frame
 * @param frame the frame
 * @param frame_size number of bytes in @a frame
 */
static void
handle_frame (uint16_t interface,
              const void *frame,
              size_t frame_size)
{
  if (interface > num_ifc)
    abort ();
  parse_frame (&gifc[interface - 1],
               frame,
               frame_size);
}


/**
 * Find network interface by @a name.
 *
 * @param name name to look up by
 * @return NULL if @a name was not found
 */
static struct Interface *
find_interface (const char *name)
{
  for (int i = 0; i<num_ifc; i++)
    if (0 == strcasecmp (name,
                         gifc[i].name))
      return &gifc[i];
  return NULL;
}

/**
 * The user entered an "arp" command.  The remaining
 * arguments can be obtained via 'strtok()'.
 */
static void process_cmd_arp () {
  const char *tok = strtok (NULL, " ");
  struct in_addr v4;
  struct MacAddress mac;
  struct Interface *ifc;

  if (NULL == tok){
    // print_arp_cache ();
    return;
  }
  if (1 != inet_pton (AF_INET, tok, &v4)){
    fprintf (stderr,"`%s' is not a valid IPv4 address\n", tok);
    return;
  }
  tok = strtok (NULL, " ");
  if (NULL == tok) {
    fprintf (stderr,"No network interface provided\n");
    return;
  }
  ifc = find_interface (tok);
  if (NULL == ifc){
    fprintf (stderr,"Interface `%s' unknown\n", tok);
    return;
  }
  /* TODO: do MAC lookup */
 for (int i = 0; i < MAX_ENTRIES; i++){
      if (ipCmp (&table[i].ip, &v4) == 0){
          if (memcmp (&table[i].name, tok, sizeof(char)*4) == 0){
	      print ("%02x:%02x:%02x:%02x:%02x:%02x\n",
			table[i].mac.mac[0],
			table[i].mac.mac[1],
			table[i].mac.mac[2],
			table[i].mac.mac[3],
			table[i].mac.mac[4],
			table[i].mac.mac[5]);
	      return;
          }
      }
  }

  if (check_ip_network (ifc->ip, v4, ifc->netmask) == 0){
  }

  // arp request on actual ip
  void* ptr = malloc (sizeof(struct EthernetHeader) + sizeof(struct ArpHeaderEthernetIPv4));
  uint8_t frame_size = sizeof (struct EthernetHeader) + sizeof(struct ArpHeaderEthernetIPv4);

  struct EthernetHeader neh;
  neh.dst = broadcastMac;
  neh.src = ifc->mac;
  neh.tag = htons(0x0806);

  // build arp_header
  struct ArpHeaderEthernetIPv4 newHeader ={
     .htype = htons(1),
     .ptype = htons(0x0800),
     .hlen = 6,
     .plen = 4,
     .oper = htons(1),
     .sender_ha = {0},
     .sender_pa = {0},
     .target_ha = {0},
     .target_pa = {0},
  };

  memcpy (&newHeader.sender_ha, &ifc->mac.mac, 6);
  newHeader.sender_pa = ifc->ip;

  memcpy (&newHeader.target_ha, &nullMac, 6);
  newHeader.target_pa = v4;

  //insert into frame
  memcpy (ptr, &neh, sizeof(struct EthernetHeader));
  memcpy (ptr + sizeof(struct EthernetHeader), &newHeader, sizeof(struct ArpHeaderEthernetIPv4));
  forward_to (ifc, ptr, frame_size);
  free(ptr);
}


/**
 * Parse network specification in @a net, initializing @a network and @a netmask.
 * Format of @a net is "IP/NETMASK".
 *
 * @param network[out] network specification to initialize
 * @param netmask[out] netmask specification to initialize
 * @param arg interface specification to parse
 * @return 0 on success
 */
static int
parse_network (struct in_addr *network,
               struct in_addr *netmask,
               const char *net)
{
  const char *tok;
  char *ip;
  int mask;

  tok = strchr (net, '/');
  if (NULL == tok)
  {
    fprintf (stderr,
             "Error in network specification: lacks '/'\n");
    return 1;
  }
  ip = strndup (net,
                tok - net);
  if (1 !=
      inet_pton (AF_INET,
                 ip,
                 network))
  {
    fprintf (stderr,
             "IP address `%s' malformed\n",
             ip);
    free (ip);
    return 1;
  }
  free (ip);
  tok++;
  if (1 !=
      sscanf (tok,
              "%u",
              &mask))
  {
    fprintf (stderr,
             "Netmask `%s' malformed\n",
             tok);
    return 1;
  }
  if (mask > 32)
  {
    fprintf (stderr,
             "Netmask invalid (too large)\n");
    return 1;
  }
  netmask->s_addr = htonl (~(uint32_t) ((1LLU << (32 - mask)) - 1LLU));
  return 0;
}


/**
 * Parse route from arguments in strtok() buffer.
 *
 * @param target_network[out] set to target network
 * @param target_netmask[out] set to target netmask
 * @param next_hop[out] set to next hop
 * @param ifc[out] set to target interface
 */
static int
parse_route (struct in_addr *target_network,
             struct in_addr *target_netmask,
             struct in_addr *next_hop,
             struct Interface **ifc)
{
  char *tok;

  tok = strtok (NULL, " ");
  if ( (NULL == tok) ||
       (0 != parse_network (target_network,
                            target_netmask,
                            tok)) )
  {
    fprintf (stderr,
             "Expected network specification, not `%s'\n",
             tok);
    return 1;
  }
  tok = strtok (NULL, " ");
  if ( (NULL == tok) ||
       (0 != strcasecmp ("via",
                         tok)))
  {
    fprintf (stderr,
             "Expected `via', not `%s'\n",
             tok);
    return 1;
  }
  tok = strtok (NULL, " ");
  if ( (NULL == tok) ||
       (1 != inet_pton (AF_INET,
                        tok,
                        next_hop)) )
  {
    fprintf (stderr,
             "Expected next hop, not `%s'\n",
             tok);
    return 1;
  }
  tok = strtok (NULL, " ");
  if ( (NULL == tok) ||
       (0 != strcasecmp ("dev",
                         tok)))
  {
    fprintf (stderr,
             "Expected `dev', not `%s'\n",
             tok);
    return 1;
  }
  tok = strtok (NULL, " ");
  *ifc = find_interface (tok);
  if (NULL == *ifc)
  {
    fprintf (stderr,
             "Interface `%s' unknown\n",
             tok);
    return 1;
  }
  return 0;
}

void updateInterfaceSettings(struct Interface *ifc, struct in_addr *target_network, struct in_addr *target_netmask) {
  if (ifc == NULL || target_network == NULL || target_netmask == NULL) {
    return;
  }
  ifc->ip = *target_network;
  ifc->netmask = *target_netmask;
}

/**
 * Add a route.
 */
static void process_cmd_route_add () {
  struct in_addr target_network;
  struct in_addr target_netmask;
  struct in_addr next_hop;
  struct Interface *ifc;

  if (0 != parse_route (&target_network,
                        &target_netmask,
                        &next_hop,
                        &ifc))
    return;
  //add entry to routing table
  struct TableEntry content;
  content.target_network = target_network;
  content.netmask = target_netmask;
  content.nextHop = next_hop;

  struct Interface interface = *ifc;

  // Update interface
  updateInterfaceSettings(&interface, &target_network, &target_netmask);
  content.interface = interface;

  memcpy(&routingTable[routingTableIndex], &content,sizeof(struct TableEntry));
  routingTableIndex++;
}



/**
 * Delete a route.
 */
static void process_cmd_route_del (){
  struct in_addr target_network;
  struct in_addr target_netmask;
  struct in_addr next_hop;
  struct Interface *ifc;

  if (0 != parse_route (&target_network, &target_netmask, &next_hop, &ifc))
    return;

  /* TODO: Delete routing table entry */
  for (int i = 0; i < MAX_ENTRIES; i++){
    if (ipCmp (&routingTable[i].target_network, &target_network) == 0
  	  && ipCmp (&routingTable[i].netmask, &target_netmask) == 0
  	  && ipCmp (&routingTable[i].nextHop, &next_hop) == 0){
  	  }

  }
}


/**
 * Print out the routing table.
 */
static void process_cmd_route_list (){
  print("Route List\n");
  for (int i = 0; i < routingTableIndex; i++){
    char buf[INET_ADDRSTRLEN];
    char buf1[INET_ADDRSTRLEN];
    char buf2[INET_ADDRSTRLEN];
    struct in_addr *target_network = &routingTable[i].target_network;
    struct in_addr *netmask = &routingTable[i].netmask;
    struct in_addr *nextHop = &routingTable[i].nextHop;
    struct Interface *ifc = &routingTable[i].interface;
    print("%s/%s -> %s (%4s)\n",
              inet_ntop(AF_INET, target_network, buf, sizeof(buf)),
              inet_ntop(AF_INET, netmask, buf1, sizeof(buf1)),
              inet_ntop(AF_INET, nextHop, buf2, sizeof(buf2)),
              ifc->name);
    }
}


/**
 * The user entered a "route" command.  The remaining
 * arguments can be obtained via 'strtok()'.
 */
static void process_cmd_route (){
  char *subcommand = strtok (NULL, " ");

  if (NULL == subcommand)
    subcommand = "list";
  if (0 == strcasecmp ("add",
                       subcommand))
    process_cmd_route_add ();
  else if (0 == strcasecmp ("del",
                            subcommand))
    process_cmd_route_del ();
  else if (0 == strcasecmp ("list",
                            subcommand))
    process_cmd_route_list ();
  else
    fprintf (stderr,
             "Subcommand `%s' not understood\n",
             subcommand);
}


/**
 * Parse network specification in @a net, initializing @a ifc.
 * Format of @a net is "IPV4:IP/NETMASK".
 *
 * @param ifc[out] interface specification to initialize
 * @param arg interface specification to parse
 * @return 0 on success
 */
static int parse_network_arg(struct Interface *ifc, const char *net) {
  if (0 != strncasecmp(net, "IPV4:", strlen("IPV4:"))) {
    fprintf(stderr, "Interface specification `%s' does not start with `IPV4:'\n", net);
    return 1;
  }

  net += strlen("IPV4:");
  return parse_network(&ifc->ip, &ifc->netmask, net);
}


/**
 * Parse interface specification @a arg and update @a ifc.  Format is
 * "IFCNAME[IPV4:IP/NETMASK]=MTU".  The "=MTU" is optional.
 *
 * @param ifc[out] interface specification to initialize
 * @param arg interface specification to parse
 * @return 0 on success
 */
static int
parse_cmd_arg (struct Interface *ifc,
               const char *arg)
{
  const char *tok;
  char *nspec;

  ifc->mtu = 1500 + sizeof (struct EthernetHeader); /* default in case unspecified */
  tok = strchr (arg, '[');
  if (NULL == tok)
  {
    fprintf (stderr,
             "Error in interface specification: lacks '['");
    return 1;
  }
  ifc->name = strndup (arg,
                       tok - arg);
  arg = tok + 1;
  tok = strchr (arg, ']');
  if (NULL == tok)
  {
    fprintf (stderr,
             "Error in interface specification: lacks ']'");
    return 1;
  }
  nspec = strndup (arg,
                   tok - arg);
  if (0 !=
      parse_network_arg (ifc,
                         nspec))
  {
    free (nspec);
    return 1;
  }
  free (nspec);
  arg = tok + 1;
  if ('=' == arg[0])
  {
    int mtu;

    if (1 != (sscanf (&arg[1],
                      "%u",
                      &mtu)))
    {
      fprintf (stderr,
               "Error in interface specification: MTU not a number\n");
      return 1;
    }
    if (mtu < 400)
    {
      fprintf (stderr,
               "Error in interface specification: MTU too small\n");
      return 1;
    }
    if (mtu > UINT16_MAX)
    {
      fprintf (stderr,
               "Error in interface specification: MTU too large\n");
      return 1;
    }
    ifc->mtu = mtu + sizeof (struct EthernetHeader);
#if DEBUG
    fprintf (stderr,
             "Interface %s has MTU %u\n",
             ifc->name,
             (int) ifc->mtu);
#endif
  }
  //add the interface to the routingTable
  struct Interface* temp = ifc;

  //save network address
  routingTable[routingTableIndex].target_network.s_addr = temp->ip.s_addr & temp->netmask.s_addr;

  //save netmask
  routingTable[routingTableIndex].netmask = temp->netmask;

  //set nextHop to zero
  memset(&routingTable[routingTableIndex].nextHop.s_addr, 0, sizeof(struct in_addr));

  routingTableIndex++;

  return 0;
}


/**
 * Handle control message @a cmd.
 *
 * @param cmd text the user entered
 * @param cmd_len length of @a cmd
 */
static void handle_control (char *cmd, size_t cmd_len){
  const char *tok;

  cmd[cmd_len - 1] = '\0';
  tok = strtok (cmd,
                " ");
  if (NULL == tok)
    return;
  if (0 == strcasecmp (tok,
                       "arp"))
    process_cmd_arp ();
  else if (0 == strcasecmp (tok,
                            "route"))
    process_cmd_route ();
  else
    fprintf (stderr,
             "Unsupported command `%s'\n",
             tok);
}


/**
 * Handle MAC information @a mac
 *
 * @param ifc_num number of the interface with @a mac
 * @param mac the MAC address at @a ifc_num
 */
static void handle_mac (uint16_t ifc_num, const struct MacAddress *mac) {
  if (ifc_num > num_ifc)
    abort ();
  gifc[ifc_num - 1].mac = *mac;

   for(int i = 0; i < num_ifc; i++){
        routingTable[i].interface = gifc[i];
  }
}


/**
 * Launches the router.
 *
 * @param argc number of arguments in @a argv
 * @param argv binary name, followed by list of interfaces to switch between
 * @return not really
 */
int main (int argc, char **argv){
  struct Interface ifc[argc];

  memset (ifc, 0, sizeof (ifc));
  num_ifc = argc - 1;
  gifc = ifc;
  for (int i = 1; i<argc; i++){
    struct Interface *p = &ifc[i - 1];

    ifc[i - 1].ifc_num = i;
    if (0 != parse_cmd_arg (p,argv[i]))
      abort ();
  }
  memset (broadcastMac.mac, 0xff, sizeof(uint8_t)*6);
  memset (nullMac.mac, 0x00, sizeof(uint8_t)*6);
  memset (&nullInAddr, 0x00, sizeof(struct in_addr));

  loop (&handle_frame,&handle_control,&handle_mac);
  for (int i = 1; i<argc; i++)
    free (ifc[i - 1].name);
  return 0;
}
