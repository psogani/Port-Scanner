#ifndef _LIB_H
#define _LIB_H

#include "setup.h"

#define SYN_SCAN     0
#define ACK_SCAN     1
#define NULL_SCAN    2
#define FIN_SCAN     3
#define XMAS_SCAN    4
#define UDP_SCAN     5
#define UNKNOWN_SCAN 6

#define ETHERNET_FRAME_SIZE 14

/* Port status */
#define OPEN		1
#define CLOSED		2
#define FILTERED	3
#define UNFILTERED	4
#define OPENORFILTERED	5
#define UNKNOWN		-1

typedef struct {
  char * destIp;
  int destinationPort;
  int scanType;
  int threadId;
  bool selected;
} Job;

typedef struct {
  char destIp[INET_ADDRSTRLEN];
  int destinationPort;
  int scanType;
  int portStatus;
} JobResult;

struct pseudo_header {
  u_int32_t src;          // source ip address
  u_int32_t dst;          // destination ip address
  u_char mbz;             // 8 reserved bits (all 0)
  u_char proto;           // protocol field of ip header
  u_int16_t len;          // tcp length (both header and data
};

//DNS header structure - referenced from http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
struct DNS_HEADER
{
  unsigned short id; // identification number
 
  unsigned char rd :1; // recursion desired
  unsigned char tc :1; // truncated message
  unsigned char aa :1; // authoritive answer
  unsigned char opcode :4; // purpose of message
  unsigned char qr :1; // query/response flag
 
  unsigned char rcode :4; // response code
  unsigned char cd :1; // checking disabled
  unsigned char ad :1; // authenticated data
  unsigned char z :1; // its z! reserved
  unsigned char ra :1; // recursion available
 
  unsigned short q_count; // number of question entries
  unsigned short ans_count; // number of answer entries
  unsigned short auth_count; // number of authority entries
  unsigned short add_count; // number of resource entries
};
 
//Constant sized fields of query structure
struct QUESTION
{
  unsigned short qtype;
  unsigned short qclass;
};
 
//Constant sized fields of the resource record structure
struct R_DATA
{
  unsigned short type;
  unsigned short _class;
  unsigned int ttl;
  unsigned short data_len;
};
 
//Pointers to resource record contents
struct RES_RECORD
{
  unsigned char *name;
  struct R_DATA *resource;
  unsigned char *rdata;
};
 
//Structure of a Query
typedef struct
{
  unsigned char *name;
  struct QUESTION *ques;
} QUERY;

int validateIP(string ipAddress);
int validateScan(char *scanType);
void separatePorts(char *portToken, ps_args_t * ps_args);
bool isLocalhost(char *ipAddress);
void getLocalIp(char *ipAddress, char *dev);
unsigned short calculateChecksum(unsigned short *addr, int len);
bool isLocalhost(char *ipAddress);
void *threadHepler(void *arg);
void readIpFromFile(ps_args_t* ps_args, char *fileName);

#endif
