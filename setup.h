#ifndef _SETUP_H
#define _SETUP_H

#include <iostream>
#include <fstream>

#include <cstring>
#include <pcap/pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <vector>
#include <ctime>
#include <sys/types.h>
#include <ifaddrs.h>
#include <math.h>
#include <algorithm>
#include <signal.h>
#include <chrono>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>

using namespace std;

typedef struct {
  vector<int> portList;
  vector<int> scanList;
  vector<string> ipAddressList;
  int numberOfThreads;
  //char destIp[INET_ADDRSTRLEN];
  bool ipFlag;
  bool fileFlag;
  bool prefixFlag;
} ps_args_t;

void usage(FILE * file);
void parse_args(int argc,  char * argv[], ps_args_t * ps_args);

#endif
