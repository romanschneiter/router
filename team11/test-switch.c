
/**
 * @file test-switch.c
 * @brief Testcase for the 'switch'.  Must be linked with harness.c.
 * @author Christian Schmidhalter, Roman Schneiter, Gabril Iskender, Basil
 */
#include "harness.h"

/**
 * Set to 1 to enable debug statments.
 */
#define DEBUG 1

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
// SWITCH TESTS (MULTICAST):


/**
 * Run test with @a prog.
 * @param prog command to test
 * @return 0 on success, non-zero on failure
 */
static int
test_mc0 (const char *prog)
{
  char my_frame[1400];

  int
  send_frame ()
  { 
    tsend (1,
           my_frame,
           sizeof (my_frame));
    return 0;
  };

  int
  expect_broadcast ()
  {
    uint64_t ifcs = (1 << 1) | (1 << 2); /* eth1 and eth2 */

    return trecv (1, /* expect *two* replies */
                  &expect_multicast,
                  &ifcs,
                  my_frame,
                  sizeof (my_frame),
                  UINT16_MAX /* ignored */);
  };

  char *argv[] = {
    (char *) prog,
    "eth0",
    "eth1",
    "eth2",
    "eth3",
    "eth4",
    NULL
  };

  struct Command cmd[] = {
    { "send frame", &send_frame },
    { "end", &expect_silence },
    { NULL }
  };
  
    // dest
  my_frame[0]= 0x0;
  my_frame[1]= 0x0;
  my_frame[2]= 0x0;
  my_frame[3]= 0x0;
  my_frame[4]= 0x0;
  my_frame[5]= 0x0;

  // source
  my_frame[6]= 0x1; // 0x1 illegeal source mac (I/G bit)
  my_frame[7]= 0x0;
  my_frame[8]= 0x0;
  my_frame[9]= 0x0;
  my_frame[10]= 0x0;
  my_frame[11]= 0x0;

  for (unsigned int i = 12; i<sizeof (my_frame); i++){
    my_frame[i] = random ();

  }
  
  return meta (cmd,
               (sizeof (argv) / sizeof (char *)) - 1,
               argv);
}




/**
 * Run test with @a prog.  Check that with just 1 interface, the hub does nothing.
 * @param prog command to test
 * @return 0 on success, non-zero on failure
 */
static int
test_mc00 (const char *prog)
{
  char my_frame[1400];

  int
  send_frame () // from each source
  {
    
    tsend (1, // source
           my_frame,
           sizeof (my_frame));
    return 0;
  };

  int
  expect_broadcast ()
  {
    uint64_t ifcs = (1 << 1) | (1 << 2); /* eth1 and eth2 */

    return trecv (1, /* expect *two* replies */
                  &expect_multicast,
                  &ifcs,
                  my_frame,
                  sizeof (my_frame),
                  UINT16_MAX /* ignored */);
  };

  char *argv[] = {
    (char *) prog,
    "eth0",
    "eth1",
    "eth2",
    "eth3",
    "eth4",
    NULL
  };

  struct Command cmd[] = {
    { "send frame", &send_frame },
    { "end", &expect_silence },
    { NULL }
  };

  // dest
  my_frame[0]= 0x02;
  my_frame[1]= 0x02;
  my_frame[2]= 0x03;
  my_frame[3]= 0x04;
  my_frame[4]= 0x05;
  my_frame[5]= 0x06;

  // source
  my_frame[6]= 0x02;
  my_frame[7]= 0x02;
  my_frame[8]= 0x03;
  my_frame[9]= 0x04;
  my_frame[10]= 0x05;
  my_frame[11]= 0x06;

  for (unsigned int i = 12; i<sizeof (my_frame); i++){
    my_frame[i] = random (); /* completely randomize frame */

  }

  return meta (cmd,
               (sizeof (argv) / sizeof (char *)) - 1,
               argv);
}


/**
 * Run test with @a prog. Unicast
 * @param prog command to test
 * @return 0 on success, non-zero on failure
 */
static int
test_uc0 (const char *prog)
{
  char my_frame[1400];
  char my_frame2[1400];

  // prepare frame
  for (unsigned int i = 0; i<sizeof (my_frame); i++){
      my_frame[i] = random ();
      my_frame2[i] = random();
  }

  int
  send_frame ()
  {
    set_source_mac(my_frame,1);
    tsend (1,
           my_frame,
           sizeof (my_frame));
    return 0;
  };
  int
  expect_broadcast ()
  {
    uint64_t ifcs = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4); // eth1-eth4
    return trecv (3, // expect *four* replies
                  &expect_multicast,
                  &ifcs,
                  my_frame,
                  sizeof (my_frame),
                  UINT16_MAX ); // ignored
  };

  int
  send_frame2()
  {
    set_source_mac(my_frame2, 2); // from 2
    set_dest_mac(my_frame2, 1); // to 1
    tsend ( 2,
           my_frame2,
           sizeof (my_frame2));
    return 0;
  };

  int
  expect_frame2()
  {
    uint64_t ifc = (1 << 1); /* eth1 */
    return trecv (0,  /* expect *one* replies */
                  &expect_frame,
                  &ifc,
                  my_frame2,
                  sizeof (my_frame2),
                  1);
  };

  char *argv[] = {
    (char *) prog,
    "eth0",
    "eth1",
    "eth2",    
    "eth3",
    "eth4",
    NULL
  };

  struct Command cmd[] = {
    { "send frame", &send_frame },
    { "check broadcast", &expect_broadcast },
    { "send frame2 back", &send_frame2},
    { "check frame", &expect_frame2},
    { "end", &expect_silence },
    { NULL }
  };
 
  return meta (cmd,
               (sizeof (argv) / sizeof (char *)) - 1,
               argv);
}


/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
// HUB COPY CODE (BROADCAST):

/**
 * Run test with @a prog.  Check that with just 1 interface, the hub does nothing.
 * @param prog command to test
 * @return 0 on success, non-zero on failure
 */

static int
test_bc0 (const char *prog)
{
  char my_frame[1400];
  int
  send_frame ()
  {
    tsend (1,
           my_frame,
           sizeof (my_frame));
    return 0;
  };

  char *argv[] = {
    (char *) prog,
    "eth0",
    NULL
  };
  struct Command cmd[] = {
    { "send frame", &send_frame },
    { "expect nothing", &expect_silence },
    { NULL }
  };

  for (unsigned int i = 0; i<sizeof (my_frame); i++)
    my_frame[i] = random (); /* completely randomize frame */
  return meta (cmd,
               (sizeof (argv) / sizeof (char *)) - 1,
               argv);
}

/**
 * Run test with @a prog. Simple forwarding of one frame to all
 * other interfaces.
 *
 * @param prog command to test
 * @return 0 on success, non-zero on failure
 */
static int
test_bc1 (const char *prog)
{
  char my_frame[1400];
  int
  send_frame ()
  {
    tsend (1,
           my_frame,
           sizeof (my_frame));
    return 0;
  };

  int
  expect_broadcast ()
  {
    uint64_t ifcs = (1 << 1) | (1 << 2); /* eth1 and eth2 */

    return trecv (1, /* expect *two* replies */
                  &expect_multicast,
                  &ifcs,
                  my_frame,
                  sizeof (my_frame),
                  UINT16_MAX /* ignored */);
  };

  char *argv[] = {
    (char *) prog,
    "eth0",
    "eth1",
    "eth2",
    NULL
  };

  struct Command cmd[] = {
    { "send frame", &send_frame },
    { "check broadcast", &expect_broadcast },
    { "end", &expect_silence },
    { NULL }
  };

  for (unsigned int i = 0; i<sizeof (my_frame); i++)
    my_frame[i] = random (); /* completely randomize frame */

  return meta (cmd,
               (sizeof (argv) / sizeof (char *)) - 1,
               argv);
}


/**
 * Run test with @a prog.  Forward frames from all interfaces to all
 * other interfaces.
 *
 * @param prog command to test
 * @return 0 on success, non-zero on failure
 */
static int
test_bc123 (const char *prog)
{
  char my_frame[1400];
  unsigned int src = 1;
  uint64_t ifcs = 0;
  int
  send_frame ()
  {
    tsend (src,
           my_frame,
           sizeof (my_frame));
    ifcs = (1 << 0) | (1 << 1) | (1 << 2); /* eth0-eth2 */
    ifcs -= (1 << (src - 1));
    src++;
    return 0;
  };
  int
  expect_broadcast ()
  {
    return trecv (1, /* expect *two* replies */
                  &expect_multicast,
                  &ifcs,
                  my_frame,
                  sizeof (my_frame),
                  UINT16_MAX /* ignored */);
  };

  char *argv[] = {
    (char *) prog,
    "eth0",
    "eth1",
    "eth2",
    NULL
  };

  struct Command cmd[] = {
    { "send frame", &send_frame },
    { "check broadcast", &expect_broadcast },
    { "send frame", &send_frame },
    { "check broadcast", &expect_broadcast },
    { "send frame", &send_frame },
    { "check broadcast", &expect_broadcast },
    { "end", &expect_silence },
    { NULL }
  };
  for (unsigned int i = 0; i<sizeof (my_frame); i++)
    my_frame[i] = random (); /* completely randomize frame */
  return meta (cmd,
               (sizeof (argv) / sizeof (char *)) - 1,
               argv);
}

/**
 * Run test with @a prog.  Forward large frame.
 *
 * @param prog command to test
 * @return 0 on success, non-zero on failure
 */
static int
test_bc_large (const char *prog)
{
  char my_frame[14000];
  int
  send_frame ()
  {
    tsend (1,
           my_frame,
           sizeof (my_frame));
    return 0;
  };
  int
  expect_broadcast ()
  {
    uint64_t ifcs = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4); /* eth1-eth4 */

    return trecv (3, /* expect *four* replies */
                  &expect_multicast,
                  &ifcs,
                  my_frame,
                  sizeof (my_frame),
                  UINT16_MAX /* ignored */);
  };

  char *argv[] = {
    (char *) prog,
    "eth0",
    "eth1",
    "eth2",
    "eth3",
    "eth4",
    NULL
  };
  struct Command cmd[] = {
    { "send frame", &send_frame },
    { "check broadcast", &expect_broadcast },
    { "end", &expect_silence },
    { NULL }
  };

  for (unsigned int i = 0; i<sizeof (my_frame); i++)
    my_frame[i] = random (); /* completely randomize frame */
  return meta (cmd,
               (sizeof (argv) / sizeof (char *)) - 1,
               argv);
}

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
// MAIN:

/**
 * Call with path to the hub program to test.
 */
int
main (int argc,
      char **argv)
{
  unsigned int grade = 0;
  unsigned int possible = 0;
  struct Test
  {
    const char *name;
    int (*fun)(const char *arg);
  } tests[] = {
    //bug 1
      //{ "normal broadcast", &test_bc1 }, //bug 1
      //{ "back and forth", &test_bc123 }, //bug 1
      { "large frame", &test_bc_large }, // bug 1

      //{ "source is destination", &test_mc00},  // reference switch sends something back
      { "illegal mac", &test_mc0},  // bug1 bug2 bug3
      { "check unicast", &test_uc0},  // bug1 bug3

    { NULL, NULL }
  };

  if (argc != 2)
  {
    fprintf (stderr,
             "Call with HUB program to test as 1st argument!\n");
    return 1;
  }
  for (unsigned int i = 0; NULL != tests[i].fun; i++)
  {
    if (0 == tests[i].fun (argv[1]))
      grade++;
    else
      fprintf (stdout,
               "Failed test `%s'\n",
               tests[i].name);
    possible++;
  }
  fprintf (stdout,
           "Final grade: %u/%u\n",
           grade,
           possible);

  if(grade != possible){
    return 1;
  }else{
    return 0;
  }
}
