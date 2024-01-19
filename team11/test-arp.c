/**
 * @file test-arp.c
 * @brief Testcase for the 'arp'.  Must be linked with harness.c.
 * @author Christian Schmidhalter, Roman Schneiter, Gabril Iskender, Basil Clematide
 */
#include "harness.h"

/**
 * Set to 1 to enable debug statments.
 */
#define DEBUG 1

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
// TESTS:

/*
You must implement and submit your own test cases by pretend-
ing to be the network driver (see below) and sending ARP requests or
command-line inputs to your program and verifying that it outputs the
correct frames. Additionally, you should perform interoperability tests
against existing implementations (i.e. other notebooks from your team to
ensure that your ARP protocol implementation integrates correctly with 
other implementations).
*/

// todo correct ints
struct ArpFrame{
    //Hardware type (HTYPE)
    uint16_t HTYPE;
    //Protocol type (PTYPE)
    uint16_t PTYPE;
    //Hardware length (HLEN)
    uint8_t HLEN;
    //Protocol length (PLEN)
    uint8_t PLEN;
    //Operation
    uint16_t OP; 
    //Sender hardware address (SHA)
    struct MacAddress SHA;
    //Sender protocol address (SPA)
    struct in_addr SPA;
    //Target hardware address (THA)
    struct MacAddress THA;
    //Target protocol address (TPA)
    struct in_addr TPA;
};

/**
 * Run test with @a prog.
 *
 * @param prog command to test
 * @return 0 on success, non-zero on failure
 */
static int test_arp0(const char *prog)
{

  char my_frame[18] = "arp 10.0.0.4 eth2\0"; // send command

  int send_frame() {
      tsend(0, my_frame, sizeof(my_frame));
      return 0;
  }

  int expect_broadcast() {
      
      // broadcast frame
      int bcfSize = sizeof(struct EthernetHeader) + sizeof(struct ArpFrame);
      char bcf[bcfSize];

      // ethernet header        
      struct EthernetHeader eh;
      eh.tag = htons(0x0806); // 0x0806 EtherType value is used to identify ARP frames

      // set destination and source IP
      struct in_addr sourceIP;
      struct in_addr destinationIP;

      inet_aton("10.0.0.4", &sourceIP);
      inet_aton("10.0.0.4", &destinationIP);

      // set destination and source Mac
      char tmpEhBuffer[sizeof(struct EthernetHeader)];
      set_source_mac(tmpEhBuffer, 3);
      set_dest_mac(tmpEhBuffer, 3);

      struct EthernetHeader tmpEh;
      memcpy(&tmpEh, tmpEhBuffer, sizeof(struct EthernetHeader));

      eh.src = tmpEh.src;
      struct MacAddress bcMac;
      memset(bcMac.mac, 0xFF, sizeof(uint8_t)*6);
      eh.dst = bcMac;
      
      struct MacAddress nullMac;
      memset(nullMac.mac, 0x00, sizeof(uint8_t)*6);

      // arp frame
      struct ArpFrame arpf;
      arpf.HTYPE = htons(1);
      arpf.PTYPE = htons(0x0800);
      arpf.HLEN = 6;
      arpf.PLEN = 4;
      arpf.OP = htons(1);
      //memset(arpf.SHA, 0xFF, sizeof(uint8_t)*6);
      arpf.SHA = tmpEh.src;
      arpf.SPA = sourceIP;
      arpf.THA = nullMac;
      arpf.TPA = destinationIP;

      memcpy(bcf, &eh, sizeof(struct EthernetHeader));
      memcpy(bcf + sizeof(struct EthernetHeader), &arpf, sizeof(struct ArpFrame));

      uint64_t ifcs = 1 << 2;

      return trecv(0, 
                  &expect_multicast, 
                  &ifcs, 
                  &bcf, 
                  bcfSize, 
                  UINT16_MAX);
    };

    char *argv[] = {
    (char *) prog,
      "eth0[IPV4:10.0.0.2/24]",
      "eth1[IPV4:10.0.0.3/24]",
      "eth2[IPV4:10.0.0.4/24]",
      NULL
    };

    struct Command cmd[] = {
        { "send frame", &send_frame },
        { "check broadcast", &expect_broadcast },
        { "expect nothing", &expect_silence },
        { NULL }
    };

    return meta(cmd, (sizeof(argv) / sizeof(char *)) - 1, argv);
}

/**
 * Run test with @a prog.
 *
 * @param prog command to test
 * @return 0 on success, non-zero on failure
 */
static int test_arp1(const char *prog){
      char new_frame[18] = "arp 10.0.0.4 eth2\0";

    int send_frame() {
        tsend(0, new_frame, sizeof(new_frame));
        return 0;
    }
    
    int arp_broadcast_frame(){
       
      // broadcast frame
      int bcfSize = sizeof(struct EthernetHeader) + sizeof(struct ArpFrame);
      char bcf[bcfSize];

      // ethernet header        
      struct EthernetHeader eh;
      eh.tag = htons(0x0806); // 0x0806 EtherType value is used to identify ARP frames

      // set destination and source IP
      struct in_addr sourceIP;
      struct in_addr destinationIP;

      inet_aton("10.0.0.4", &sourceIP);
      inet_aton("10.0.0.4", &destinationIP);

      // set destination and source Mac
      char tmpEhBuffer[sizeof(struct EthernetHeader)];
      set_source_mac(tmpEhBuffer, 3);
      set_dest_mac(tmpEhBuffer, 3);

      struct EthernetHeader tmpEh;
      memcpy(&tmpEh, tmpEhBuffer, sizeof(struct EthernetHeader));

      eh.src = tmpEh.src;
      struct MacAddress bcMac;
      memset(bcMac.mac, 0xFF, sizeof(uint8_t)*6);
      eh.dst = bcMac;

      struct MacAddress nullMac;
      memset(nullMac.mac, 0x00, sizeof(uint8_t)*6);

      // arp frame
      struct ArpFrame arpf;
      arpf.HTYPE = htons(1);
      arpf.PTYPE = htons(0x0800);
      arpf.HLEN = 6;
      arpf.PLEN = 4;
      arpf.OP = htons(1);
      //memset(arpf.SHA, 0xFF, sizeof(uint8_t)*6);
      arpf.SHA = tmpEh.src;
      arpf.SPA = sourceIP;
      arpf.THA = nullMac;
      arpf.TPA = destinationIP;

      memcpy(bcf, &eh, sizeof(struct EthernetHeader));
      memcpy(bcf + sizeof(struct EthernetHeader), &arpf, sizeof(struct ArpFrame));

      uint64_t ifcs = 1 << 2;

      return trecv(1, 
                  &expect_multicast, 
                  &ifcs, 
                  &bcf, 
                  bcfSize, 
                  UINT16_MAX);
        };

    int arp_response_frame(){
        int responseframeSize = sizeof(struct EthernetHeader) + sizeof(struct ArpFrame);
        char arpResponseFrame[responseframeSize];

        //fill the frame with new data   
        struct EthernetHeader eh; // ethernet header  
        eh.tag = htons(0x0806); // 0x0806 EtherType value is used to identify ARP frames

        // set destination and source IP
        struct in_addr sourceIP;
        struct in_addr destinationIP;

        inet_aton("10.0.0.4", &sourceIP);
        inet_aton("10.0.0.4", &destinationIP);

        // set destination and source Mac
        char tmpEhBuffer[sizeof(struct EthernetHeader)];
        set_source_mac(tmpEhBuffer, 3);
        set_dest_mac(tmpEhBuffer, 3);

        struct EthernetHeader tmpEh;
        memcpy(&tmpEh, tmpEhBuffer, sizeof(struct EthernetHeader));

        eh.src = tmpEh.src;
        struct MacAddress bcMac;
        memset(bcMac.mac, 0xFF, sizeof(uint8_t)*6);
        eh.dst = tmpEh.dst;
        
        // arp frame
        struct ArpFrame arpf;
        arpf.HTYPE = htons(1);
        arpf.PTYPE = htons(0x0800);
        arpf.HLEN = 6;
        arpf.PLEN = 4;
        arpf.OP = htons(2);
        //memset(arpf.SHA, 0xFF, sizeof(uint8_t)*6);
        arpf.SHA = tmpEh.src;
        arpf.SPA = sourceIP;
        arpf.THA = tmpEh.dst;
        arpf.TPA = destinationIP;
        memcpy(arpResponseFrame, &eh, sizeof(struct EthernetHeader));
        memcpy(arpResponseFrame + sizeof(struct EthernetHeader), &arpf, sizeof(struct ArpFrame));

        struct MacAddress broadcastAddress;
        struct MacAddress nullAddress;

        tsend(3, arpResponseFrame, responseframeSize);
        return 0;
    };

    int arp_command() {
        char arp_list_frame[4] = "arp\0";
        tsend(0, arp_list_frame, sizeof (arp_list_frame));
        return 0;
    };

    int validate_arp_print(){
        char tempFrame[sizeof(struct EthernetHeader)];
        set_source_mac(tempFrame, 3);
        struct EthernetHeader ethernet_Header;
        memcpy(&ethernet_Header, tempFrame, sizeof( struct EthernetHeader));

        struct MacAddress tempAddress = ethernet_Header.src;
        char print_out[37];

        sprintf(
        print_out,
        "10.0.0.4 -> %02x:%02x:%02x:%02x:%02x:%02x (eth2)\n",
        tempAddress.mac[0], 
        tempAddress.mac[1], 
        tempAddress.mac[2], 
        tempAddress.mac[3],
        tempAddress.mac[4], 
        tempAddress.mac[5]
        );

        int type = 0; 
        return trecv(0, 
                    &expect_frame2, 
                    &type, 
                    &print_out, 
                    sizeof(print_out), 
                    0);
    };

    char *argv[] = {
        (char *) prog,
        "eth0[IPV4:10.0.0.2/24]",
        "eth1[IPV4:10.0.0.3/24]",
        "eth2[IPV4:10.0.0.4/24]",
        NULL
    };

    struct Command cmd[] = {
        { "send arp frame", &send_frame },
        { "check broadcast", &arp_broadcast_frame },
        { "send ARP response", &arp_response_frame },
        { "arp", &arp_command},
        { "check the list", &validate_arp_print },
        { "end", &expect_silence },
        { NULL }
    };
    return meta (cmd, (sizeof (argv) / sizeof (char *)) - 1, argv);  
}
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
// MAIN:

/**
 * Call with path to the arp program to test.
 */
int
main (int argc, char **argv){
  unsigned int grade = 0;
  unsigned int possible = 0;
  struct Test
  {
    const char *name;
    int (*fun)(const char *arg);
  } tests[] = {
    { "test 1", &test_arp0 }, // test arp
    { "test 2", &test_arp1 }, // test arp list
    { NULL, NULL }
  };

  if (argc != 2)
  {
    fprintf (stderr, "Call with ARP program to test as 1st argument!\n");
    return 1;
  }

  for (unsigned int i = 0; NULL != tests[i].fun; i++){
    if (0 == tests[i].fun (argv[1])){
      grade++;  
    }
    else{
      fprintf (stdout, "Failed test `%s'\n", tests[i].name);
    }
     possible++;
  }
  fprintf (stdout, "Final grade: %u/%u\n", grade, possible);

  if(grade != possible){
    return 1;
  }
  else{  
    return 0;
  }
}
