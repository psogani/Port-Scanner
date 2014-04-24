#ifndef _SCANNER_H
#define _SCANNER_H

#include "setup.h"
#include "lib.h"

#define BUFF 65535

class Scanner {
  public:

    //ScanRequest scanRequest;
    vector<Job> jobs;
    vector<JobResult> jobResults;
    char *localIpAddress;
    char *dev;
    pcap_t *handle;
    vector<vector<int> > workers;
    vector<pthread_t> workerThreads;
    pthread_mutex_t getJobMutex;
    pthread_mutex_t tcpMutex;
    pthread_mutex_t udpMutex;
    int numberOfThreads;
    int totalJobs;
    int remainingJobs;
  	  
  //methods
  Scanner(ps_args_t *ps_args);
  static Scanner* shared(ps_args_t *ps_args);
  void createJobList(ps_args_t *ps_args);
  void handleThreads(ps_args_t *ps_args);
  void processJobs();
  void runTCPscan(Job job);
  void runUDPScan(Job job);
  Job *getJobFromQueue(int threadId);
  void initializePcapHandle(ps_args_t *ps_args);
  void printResult();
  ~Scanner();
  
};

//void processPacket(u_char *port, const struct pcap_pkthdr *header, const u_char *packet);
#endif
