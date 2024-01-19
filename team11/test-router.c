/**
 * @file test-router.c
 * @brief Testcase for the 'router'.  Must be linked with harness.c.
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


// Test fragmentation
static int test_fragmentation(const char *prog) {

/*
    uint8_t fragment1[] = {
        0x45, 0x00, 0x00, 0x34, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, // IP header
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // Payload
    };
    uint8_t fragment2[] = {
        0x45, 0x00, 0x00, 0x34, 0x00, 0x02, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, // IP header
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, // Payload
    };
    uint8_t fragment3[] = {
        0x45, 0x00, 0x00, 0x34, 0x00, 0x03, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, // IP header
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, // Payload
    };

    // verify ...

    uint8_t expectedReassembledPacket[] = {
        0x45, 0x00, 0x00, 0x64, 0x00, 0x02, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, // IP header
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // Payload
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, // Payload
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, // Payload
    };
*/
    //int isEqual = memcmp(reassembledPacket, expectedReassembledPacket, sizeof(expectedReassembledPacket));
    // equal good else bad

    char *argv[] = {
      (char *) prog,
        "eth0[IPV4:10.0.0.2/24]",
        "eth1[IPV4:10.0.0.3/24]",
        "eth2[IPV4:10.0.0.4/24]",
        NULL
    };

    struct Command cmd[] = {
        //{ "send frame", &send_frame },
        //{ "check broadcast", &expect_broadcast },
        { "expect nothing", &expect_silence },
        { NULL }
    };

    return meta(cmd, (sizeof(argv) / sizeof(char *)) - 1, argv);
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
    //{ "test fragmentation", &test_fragmentation},
    //{ "test 1", &test_arp0 }, // test arp
    //{ "test 2", &test_arp1 }, // test arp list
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
