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
 * @file switch.c
 * @brief Ethernet switch
 * @author Christian Grothoff
 */
#include "glab.h"
#include <stdbool.h>


void print_mac (const struct MacAddress *mac){
fprintf (stderr, "%02x:%02x:%02x:%02x:%02x:%02x\n",
mac->mac[0], mac->mac[1],
mac->mac[2], mac->mac[3],
mac->mac[4], mac->mac[5]);
}

int macComp(const uint8_t mac1[], const uint8_t mac2[]){
  for(int i = 0; i<6; i++){
    if(mac1[i] != mac2[i]){
        return -1;
    }
  }
  return 0;
}

/**
 * mac table structure
 */
#define MAX_ENTRIES 50

struct MacTableEntry {
  struct MacAddress macAddress;
  uint16_t portNumber;
};

struct MacTableEntry macTable[MAX_ENTRIES];
int numEntries = 0;


/**
 * gcc 4.x-ism to pack structures (to be used before structs);
 * Using this still causes structs to be unaligned on the stack on Sparc
 * (See #670578 from Debian).
 */
_Pragma("pack(push)") _Pragma("pack(1)")

struct EthernetHeader
{
  struct MacAddress dst; // 6 bytes
  struct MacAddress src; //6 bytes
  uint16_t tag; // 2 bytes
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
   * Number of this interface.
   */
  uint16_t ifc_num;
};


/**
 * Number of available contexts.
 */
static unsigned int num_ifc;

/**
 * All the contexts.
 */
static struct Interface *gifc;


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

  if (frame_size < sizeof (eh))
  {
    fprintf (stderr,
             "Malformed frame\n");
    return;
  }

  memcpy (&eh,
          frame,
          sizeof (eh));

  //src-mac-address should not be dst-mac-address
  if (macComp(eh.dst.mac, eh.src.mac)==0){
    fprintf (stderr,"SRC is DST\n");
    return;
  }

  //mulitcast check - masks least significant bit of the first byte
  if((eh.src.mac[0] & 0x01) == 0x01){
    for(int i = 0; i<num_ifc; i++){
        struct Interface *dst_ifc=&gifc[i];
        if(ifc == dst_ifc){
            continue;
        }
        if((dst_ifc->mac.mac[0] & 0x01) != 0x01){
            continue;
        }
        forward_to(dst_ifc, frame, frame_size);
    }
    return;
  }

  //create table entry
  struct MacTableEntry entry;
  entry.portNumber = (uint16_t) ifc->ifc_num;
  for (int i=0; i<6;i++){
        entry.macAddress.mac[i] = eh.src.mac[i];
  }

  //check if mac address is already in table
  bool containedMac = -1;

  //if src-mac-address is in table -> overwrite Port
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (macComp(macTable[i].macAddress.mac, eh.src.mac)==0) {
      containedMac = 0;
      macTable[i].portNumber = entry.portNumber;
      break;
    }
  }
  //If mac address isn't in table -> copy new entry in table
  if(!containedMac == 0){
    macTable[numEntries] = entry;
    numEntries++;

    //provide overflow of mac table
    if (numEntries > MAX_ENTRIES-1) {
      numEntries = 0;
    }
  }

  //check if dst-mac-address is in mac table
  struct Interface forwardToIFCofTableEntry;

  //If dst-mac is in table copy the content of table entry to Interface
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (macComp(macTable[i].macAddress.mac, eh.dst.mac)==0) {
        //forwardToIFCofTableEntry.mac = macTable[i].macAddress;
        for(int k=0; k<6; k++){
        forwardToIFCofTableEntry.mac.mac[k] = macTable[i].macAddress.mac[k];
        }
        forwardToIFCofTableEntry.ifc_num = macTable[i].portNumber;

        forward_to(&forwardToIFCofTableEntry, frame, frame_size);
        return;
    }
  }

  //if dst-mac-address is not in table -> broadcast
  for(int i = 0; i < num_ifc; i++){
    if(ifc != &gifc[i]){
        forward_to(&gifc[i], frame, frame_size);
        struct Interface *dst_ifc=&gifc[i];
    }
  }
  return;
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
 * Handle control message @a cmd.
 *
 * @param cmd text the user entered
 * @param cmd_len length of @a cmd
 */
static void
handle_control (char *cmd,
                size_t cmd_len)
{
  cmd[cmd_len - 1] = '\0';
  print ("Received command `%s' (ignored)\n",
         cmd);
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
 * Launches the switch.
 *
 * @param argc number of arguments in @a argv
 * @param argv binary name, followed by list of interfaces to switch between
 * @return not really
 */
int
main (int argc,
      char **argv)
{
  struct Interface ifc[argc - 1];

  memset (ifc,
          0,
          sizeof (ifc));
  num_ifc = argc - 1;
  gifc = ifc;
  for (unsigned int i = 1; i<argc; i++)
    ifc[i - 1].ifc_num = i;

  loop (&handle_frame,
        &handle_control,
        &handle_mac);
  return 0;
}
