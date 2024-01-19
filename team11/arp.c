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
 * @file arp.c
 * @brief ARP tool
 * @author Christian Grothoff
 */
#include "glab.h"
#include <stdbool.h>
#include <string.h>

#define MAX_ENTRIES 50

/**
 * gcc 4.x-ism to pack structures (to be used before structs);
 * Using this still causes structs to be unaligned on the stack on Sparc
 * (See #670578 from Debian).
 */
_Pragma("pack(push)") _Pragma ("pack(1)")

struct EthernetHeader
{
  struct MacAddress dst;
  struct MacAddress src;

  //See ETH_P-values.
   uint16_t tag;
 };



//ARP header for Ethernet-IPv4.
struct ArpHeaderEthernetIPv4 {
  //Must be #ARP_HTYPE_ETHERNET.
  uint16_t htype;

  //Protocol type, must be #ARP_PTYPE_IPV4
  uint16_t ptype;

  //HLEN.  Must be #MAC_ADDR_SIZE.
  uint8_t hlen;

  //PLEN.  Must be sizeof (struct in_addr) (aka 4).
  uint8_t plen;

  //Type of the operation. Request or Response
  uint16_t oper;

  //HW address of sender(MAC). We only support Ethernet.
  struct MacAddress sender_ha;

  //Layer3-address of sender. We only support IPv4.
  struct in_addr sender_pa;

  //HW address of target(MAC). We only support Ethernet.
  struct MacAddress target_ha;

  //Layer3-address of target. We only support IPv4.
  struct in_addr target_pa;
};

_Pragma("pack(pop)")

//Per-interface context.
struct Interface {
  //MAC of interface.
  struct MacAddress mac;

  //IPv4 address of interface (we only support one IP per interface!)
  struct in_addr ip;

  //IPv4 netmask of interface.
  struct in_addr netmask;

  //Name of the interface.
  char *name;

  //Interface number.
  uint16_t ifc_num;

  //MTU to enforce for this interface.
  uint16_t mtu;
};


//Number of available contexts.
static unsigned int num_ifc;

//All the contexts.
static struct Interface *gifc;

//arp-table
struct Interface table[MAX_ENTRIES];
int tableIndex = 0;
struct MacAddress broadcastMac;
struct MacAddress nullMac;

//compare two mac-addresses
int macComp(const uint8_t mac1[], const uint8_t mac2[]){
  for(int i = 0; i<6; i++){
    if(mac1[i] != mac2[i]){
        return -1;
    }
  }
  return 0;
}

//prints the mac-address to std:err
static void
print_mac (const struct MacAddress *mac) {
    print ("%02x:%02x:%02x:%02x:%02x:%02x",
    mac->mac[0], mac->mac[1],
    mac->mac[2], mac->mac[3],
    mac->mac[4], mac->mac[5]);
}


// Compares two ipv4 addresses
static int ipCmp (const struct in_addr *ip1, const struct in_addr *ip2) {
    return memcmp (ip1, ip2, sizeof (struct in_addr));
}


static int check_ip_network (struct in_addr ip1, struct in_addr ip2, struct in_addr netmask) {
   return (ip2.s_addr & netmask.s_addr) == (ip1.s_addr & netmask.s_addr);
}

static void print_frame (uint8_t* frame, uint8_t frame_size){
   for (size_t i = 0; i < frame_size; i++){
       if (i % 8 == 0){
	   print ("\n");
       }
       print ("%02x ", frame[i]);
   }
   print ("\n");
}

static void
print_ip (const struct in_addr *ip){
   char buf[INET_ADDRSTRLEN];
   print ("%s", inet_ntop (AF_INET, ip, buf, sizeof (buf)));
}


static void print_interface (struct Interface *ifc) {
   print_mac (&ifc->mac);
   print_ip (&ifc->ip);
   print_ip (&ifc->netmask);
}

//Shift 8 Bits
static uint16_t shift_bytes(uint16_t n) {
  return ((n >> 8) | (n << 8));
}

//check if ip is in same subnet
int check_ip_match (struct in_addr ip1, struct in_addr ip2, struct in_addr netmask) {
   return (ip2.s_addr & netmask.s_addr) == (ip1.s_addr & netmask.s_addr);
}

//helper function to print all information of interface
//static void print_ifc (struct Interface *ifc);




/**
 * Forward @a frame to interface @a dst.
 *
 * @param dst target interface to send the frame out on
 * @param frame the frame to forward
 * @param frame_size number of bytes in @a frame
 */
static void
forward_to (struct Interface *dst,
            const void *frame,
            size_t frame_size)
{
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
  void *ptr = (uint8_t*) frame;

  if (frame_size < sizeof (eh)) {
    fprintf (stderr, "Malformed frame\n");
    return;
  }
  memcpy (&eh,
          frame,
          sizeof (eh));
  /* DO WORK HERE */

    struct ArpHeaderEthernetIPv4 ah;

    memcpy (&ah, frame + sizeof(eh), sizeof(ah));

    //shift the fields htype, ptype, operations
    ah.htype = shift_bytes(ah.htype);
    ah.ptype = shift_bytes(ah.ptype);
    ah.oper = shift_bytes(ah.oper);


  //ARP-REQUEST
  if (ah.oper == 0x1){

  //check if this interface is the target
  if (ipCmp (&ifc->ip, &ah.target_pa) == 0) {

     //construct ethernetHeader
     struct EthernetHeader newEh;
     newEh.dst = ah.sender_ha;
     newEh.src = ifc->mac;
     newEh.tag = eh.tag;

     //construct the arp_header
     struct ArpHeaderEthernetIPv4 newAH ={
    .htype = htons(1),
	.ptype = htons(0x800),
	.hlen = 6,
	.plen = 4,
	.oper = htons(2),
	.sender_ha = {0},
	.sender_pa = {0},
	.target_ha = {0},
	.sender_pa = {0},
     };

     memcpy (&newAH.sender_ha, &ifc->mac.mac, 6);
     newAH.sender_pa = ifc->ip;

     //target is the old source mac and ip
     memcpy (&newAH.target_ha, &ah.sender_ha, 6);
     newAH.target_pa = ah.sender_pa;

     //insert into frame
     memcpy (ptr, &newEh, sizeof(struct EthernetHeader));
     memcpy (ptr + sizeof (struct EthernetHeader), &newAH, sizeof(struct ArpHeaderEthernetIPv4));

     uint8_t size = sizeof(struct EthernetHeader) + sizeof(struct ArpHeaderEthernetIPv4);

     forward_to (ifc, ptr, size);
     //
     }
     }

  //
  bool containedMacAndIp = false;
  for (unsigned int i = 0; i < MAX_ENTRIES; i++){

    //check if mac-address and ip is in table
    if (ipCmp (&table[i].ip, &ah.sender_pa) == 0){
	containedMacAndIp = true;

	//update table
	table[i].mac = ah.sender_ha;
	table[i].netmask = ifc->netmask;
	memcpy (&table[i].name, ifc->name, sizeof(ifc->name));
	table[i].ifc_num = ifc->ifc_num;
	table[i].mtu = ifc->mtu;
	break;
    }
  }
  //if not -> insert into table
    if (!containedMacAndIp){
       table[tableIndex].mac = ah.sender_ha;
       table[tableIndex].ip = ah.sender_pa;
       table[tableIndex].netmask = ifc->netmask;
       memcpy (&table[tableIndex].name, ifc->name, sizeof(ifc->name));
       table[tableIndex].ifc_num = ifc->ifc_num;
       table[tableIndex].mtu = ifc->mtu;

       //search the name and insert it
       tableIndex++;

       //provide overflow
       if(tableIndex >= MAX_ENTRIES){
  	    tableIndex = 0;
       }

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
handle_frame (uint16_t interface, const void *frame, size_t frame_size) {
  if (interface > num_ifc){
    abort ();
  }
  parse_frame (&gifc[interface - 1], frame, frame_size);
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


/*
//print ip & mac of interface
static void print_ifc (struct Interface *ifc) {
   print_ip (&ifc->ip);
   print(" -> ");
   print_mac(&ifc->mac);
   print(" (");
   //print("%s)\n", ifc->name);
}
*/

/**
 * The user entered an "arp" command.  The remaining
 * arguments can be obtained via 'strtok()'.
 */
static void
process_cmd_arp () {
  const char *tok = strtok (NULL, " ");
  struct in_addr v4;
  struct MacAddress mac;
  struct Interface *ifc;

  if (NULL == tok) {
    print_arp_cache ();
    return;
  }
  if (1 != inet_pton (AF_INET, tok, &v4)) {
    fprintf (stderr, "`%s' is not a valid IPv4 address\n", tok);
    return;
  }

  tok = strtok (NULL, " ");
  if (NULL == tok) {
    fprintf (stderr, "No network interface provided\n");
    return;
  }

  ifc = NULL;
  for (unsigned int i = 0; i<num_ifc; i++) {
    if (0 == strcasecmp (tok, gifc[i].name)) {
      ifc = &gifc[i];
      break;
    }
  }

  if (NULL == ifc){
    fprintf (stderr, "Interface `%s' unknown\n", tok);
    return;
  }

  //
  //check if ip is in table
  for (unsigned int i = 0; i < MAX_ENTRIES; i++) {
     if (ipCmp (&table[i].ip, &v4) == 0) {
	 if (memcmp (&table[i].name, tok, sizeof(char)*4) == 0) {
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
  //
  //print("IP not in Network!\n");
  if (check_ip_match (ifc->ip, v4, ifc->netmask) == 0){
	return;
  }
 //do arp request on given ip
  void* ptr = malloc (sizeof(struct EthernetHeader) + sizeof(struct ArpHeaderEthernetIPv4));
  uint8_t frame_size = sizeof(struct EthernetHeader) + sizeof(struct ArpHeaderEthernetIPv4);

  struct EthernetHeader newEh;

  newEh.dst = broadcastMac;
  newEh.src = ifc->mac;
  newEh.tag = htons(0x0806);

  //construct the arp_header
  struct ArpHeaderEthernetIPv4 newAH = {
    .htype = htons(1),
	.ptype = htons(0x0800),
	.hlen = 6,
	.plen = 4,
	.oper = htons(1),
	.sender_ha = {0},
	.sender_pa = {0},
	.target_ha.mac = {0},
	.sender_pa = {0},
     };

     //sender is my mac and ip
     memcpy (&newAH.sender_ha, &ifc->mac.mac, 6);
     newAH.sender_pa = ifc->ip;

     //target is the old source mac and ip
     memcpy (&newAH.target_ha, &nullMac, 6);
     newAH.target_pa = v4;

     //insert into frame
     memcpy (ptr, &newEh, sizeof(struct EthernetHeader));
     memcpy (ptr + sizeof (struct EthernetHeader), &newAH, sizeof(struct ArpHeaderEthernetIPv4));

     //forward frame
     forward_to (ifc, ptr, frame_size);
     free(ptr);


  }



/**
 * Parse network specification in @a net, initializing @a ifc.
 * Format of @a net is "IPV4:IP/NETMASK".
 *
 * @param ifc[out] interface specification to initialize
 * @param arg interface specification to parse
 * @return 0 on success
 */
static int
parse_network (struct Interface *ifc,
               const char *net)
{
  const char *tok;
  char *ip;
  unsigned int mask;

  if (0 !=
      strncasecmp (net,
                   "IPV4:",
                   strlen ("IPV4:")))
  {
    fprintf (stderr,
             "Interface specification `%s' does not start with `IPV4:'\n",
             net);
    return 1;
  }
  net += strlen ("IPV4:");
  tok = strchr (net, '/');
  if (NULL == tok)
  {
    fprintf (stderr,
             "Error in interface specification `%s': lacks '/'\n",
             net);
    return 1;
  }
  ip = strndup (net,
                tok - net);
  if (1 !=
      inet_pton (AF_INET,
                 ip,
                 &ifc->ip))
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
  ifc->netmask.s_addr = htonl (~(uint32_t) ((1LLU << (32 - mask)) - 1LLU));
  return 0;
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
      parse_network (ifc,
                     nspec))
  {
    free (nspec);
    return 1;
  }
  free (nspec);
  arg = tok + 1;
  if ('=' == arg[0])
  {
    unsigned int mtu;

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
    ifc->mtu = mtu + sizeof (struct EthernetHeader);
  }
  return 0;
}


/**
 * Handle control message @a cmd.
 *
 * @param cmd text the user entered
 * @param cmd_len length of @a cmd
 */
static void
handle_control (char *cmd,
                size_t cmd_len)
{
  const char *tok;

  cmd[cmd_len - 1] = '\0';
  tok = strtok (cmd,
                " ");
  if (0 == strcasecmp (tok,
                       "arp"))
    process_cmd_arp ();
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
static void
handle_mac (uint16_t ifc_num,
            const struct MacAddress *mac)
{
  if (ifc_num > num_ifc)
    abort ();
  gifc[ifc_num - 1].mac = *mac;
}


/**
 * Launches the arp tool.
 *
 * @param argc number of arguments in @a argv
 * @param argv binary name, followed by list of interfaces to switch between
 * @return not really
 */
int
main (int argc,
      char **argv)
{
  struct Interface ifc[argc];

  memset (ifc,
          0,
          sizeof (ifc));
  num_ifc = argc - 1;
  gifc = ifc;
  for (unsigned int i = 1; i<argc; i++)
  {
    struct Interface *p = &ifc[i - 1];

    ifc[i - 1].ifc_num = i;
    if (0 !=
        parse_cmd_arg (p,
                       argv[i]))
      abort ();
  }
  //set null and broadcastMac
  for (int i = 0; i < 6; i++) {
      broadcastMac.mac[i] = 0xFF;
  }
  for (int i = 0; i < 6; i++) {
      nullMac.mac[i] = 0x00;
  }

  loop (&handle_frame,
        &handle_control,
        &handle_mac);
  for (unsigned int i = 1; i<argc; i++)
    free (ifc[i - 1].name);
  return 0;
}
