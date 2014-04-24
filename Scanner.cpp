#include "setup.h"
#include "Scanner.h"

static Scanner *scannerInstance;

Scanner* Scanner::shared(ps_args_t *ps_args) {
  if(scannerInstance == NULL)
    scannerInstance = new Scanner(ps_args);
  return scannerInstance;
}

Scanner::Scanner(ps_args_t *ps_args) {
  //constructor
  
  /* check if IP address/prefix/file name is provided */
  if(!ps_args->ipFlag && !ps_args->prefixFlag && !ps_args->fileFlag) {
    cout << "IP address not specified" << endl;
    usage(stdout);
    exit(0);
  }
  
  /* Get local IP Address */
  localIpAddress = new char[INET_ADDRSTRLEN + 1];
  memset(localIpAddress, 0, INET_ADDRSTRLEN + 1);
  dev = new char[10];
  memset(dev, 0, 10);
  getLocalIp(localIpAddress, dev);
  //cout << "Local IP Address: " << localIpAddress << endl;
  //cout << "Device name: " << dev << endl;
  
  
  numberOfThreads = ps_args->numberOfThreads;
  /* if multi-threading, initialize the mutexs */
  if(numberOfThreads > 0) {
    pthread_mutex_init(&getJobMutex, NULL);
    pthread_mutex_init(&udpMutex, NULL);
    pthread_mutex_init(&tcpMutex, NULL);
  }
  
  cout << "Scanning..." << endl;
  
  if(ps_args->portList.empty()) {		// if portList is empty, initialize portList to 1-1024
    cout << "Initializing port list to 1-1024" << endl;
    for(int port = 1; port < 1025; port++) {
      ps_args->portList.push_back(port);
    }
  }
  
  if(ps_args->scanList.empty()) {		// if scanList is empty, perform all scans
    cout << "Initializing scan list to include all scans" << endl;
    for(int scan = SYN_SCAN; scan < UNKNOWN_SCAN; scan++) {
      ps_args->scanList.push_back(scan);
    }
  }
}

void Scanner::createJobList(ps_args_t *ps_args) {
  //cout << "Creating job list.." << endl;
  
  for(vector<string>::iterator ipAddress = ps_args->ipAddressList.begin(); ipAddress != ps_args->ipAddressList.end(); ++ipAddress) {

    for(vector<int>::iterator port = ps_args->portList.begin(); port != ps_args->portList.end(); ++port) {
      //cout << "Port number: " << *port << endl;

      for(vector<int>::iterator scan = ps_args->scanList.begin(); scan != ps_args->scanList.end(); ++scan) {
        //cout << "Scan type: " << *scan << endl;
        string ip = *ipAddress;
        const char *ipAddr = ip.c_str();
        Job job = {(char *) ipAddr, *port, *scan, -1, false};
        jobs.push_back(job);
      }
    }
  }

  totalJobs = ps_args->ipAddressList.size() * ps_args->portList.size() * ps_args->scanList.size();
  remainingJobs = totalJobs;				// initially remainingJobs = totalJobs
  cout << "Total jobs: " << totalJobs << endl;
  
  /* Print job list */
  /*for(int i = 0; i < totalJobs; i++) {
    Job job = jobs[i];
    cout << "Job:"<< endl;
    cout << "IP: " << job.destIp << "\t";
    cout << "Port: \t" << job.destinationPort << "\t";
    cout << "Scan: " << job.scanType << "\t";
    cout << endl;
  }*/
}

void Scanner::handleThreads(ps_args_t *ps_args) {
  //cout << "Handling threads" << endl;
  
  if(numberOfThreads == 0) { //no threads
    processJobs();
  }
  
  else {  
    cout << "Number of threads: " << numberOfThreads << endl;
    workerThreads.resize(numberOfThreads);
    int threadId[numberOfThreads];
    for(int i = 0; i < numberOfThreads; i++) {
      threadId[i] = i;
      usleep(100);
      //cout << "I: " << i << endl;
      pthread_create(&workerThreads[i], NULL, threadHepler, &threadId[i]);
    }
    
    usleep(100);
    void *result;

    for(int i = 0; i < numberOfThreads; i++) {
      pthread_join(workerThreads[i], &result);
    }
  }
  
}

void Scanner::processJobs() {
  for(vector<Job>::iterator j = jobs.begin(); j != jobs.end(); ++j) {
    cout << "Processing job: " << j - jobs.begin() + 1 << endl;
    Job job = *j;

    if(job.scanType == UDP_SCAN) {
      runUDPScan(job);
    }

    else {
      runTCPscan(job);
    }
    
    remainingJobs--;
  }
}

void *threadHepler(void *arg) {
  int *data = reinterpret_cast<int*>(arg);		// referenced from http://stackoverflow.com/a/1640541
  int threadId = *data;
  //cout << "Thread ID: " << threadId << endl;
  Job job;
  Job *jobPointer;
  
  while(scannerInstance->remainingJobs > 0) {
    do {
      jobPointer = scannerInstance->getJobFromQueue(threadId);
    } while(jobPointer == NULL && scannerInstance->remainingJobs > 0);

    //cout << "Got job" << endl;
    if(jobPointer != NULL) {
      job = *jobPointer;
      //cout << "Got job. Thread ID: " << threadId << endl;
      /*cout << "Job:"<< endl;
      cout << "IP: " << job.destIp << "\t";
      cout << "Port: \t" << job.destinationPort << "\t";
      cout << "Scan: " << job.scanType << "\t";
      cout << endl;*/
    
      if(job.scanType == UDP_SCAN) {
        scannerInstance->runUDPScan(job);
      }

      else {
        scannerInstance->runTCPscan(job);
      }
    }
  }
}

Job* Scanner::getJobFromQueue(int threadId) {

  pthread_mutex_lock(&getJobMutex);
  
  Job *job = NULL;
  int randomInt;
  int tries = 0;
  
  randomInt = rand() % totalJobs;
  //cout << "Random int: " << randomInt << endl;
  job = &jobs[randomInt];
  if(!job->selected) {
    job->selected = true;
    job->threadId = threadId;
    remainingJobs--;
    pthread_mutex_unlock(&getJobMutex);
    return job;
  }

  job = NULL;
  pthread_mutex_unlock(&getJobMutex);
  return job;
}

void Scanner::runTCPscan(Job job) {

  pthread_mutex_lock(&tcpMutex);
  int result;

  char buffer[4096];
  int rawSocket;
  struct sockaddr_in sin;
  struct ip *ip = (struct ip *) buffer;
  struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct ip));

  /* Packet */
  memset(buffer, 0, 4096);						// clear the buffer
  
  ip->ip_hl = 0x5;							// header length = 5
  ip->ip_v = 0x4;							// version = 4
  ip->ip_tos = 0x0;							// type of service
  ip->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);		// no payload
  ip->ip_id = htonl(12345);						// simple id
  ip->ip_off = 0x0;							// no fragmentation
  ip->ip_ttl = 225;							// time to live
  ip->ip_p = IPPROTO_TCP;						// protocol
  ip->ip_src.s_addr = inet_addr(localIpAddress);				// source - local ip 
  ip->ip_dst.s_addr = inet_addr(job.destIp);				// destination ip
  ip->ip_sum = calculateChecksum((unsigned short *)&ip, sizeof(ip));	// checksum

  tcp->th_sport = htons(2345);						// source port
  tcp->th_dport = htons(job.destinationPort);				// destination port
  tcp->th_seq = rand() % 100 + 1;						// random TCP sequence
  tcp->th_ack = 0;							// no ACK
  //tcp->th_offx2 = 0x50;                       				// 50h
  tcp->th_off = sizeof(struct tcphdr) / 4;
  tcp->th_win = (65535);                      				// maximum window size
  tcp->th_urp = 0;                            				// no urgent pointer
  tcp->th_sum = 0;                            				// tcp header sum

  switch(job.scanType) {
    case SYN_SCAN:
      tcp->th_flags = TH_SYN;
      break;

   case ACK_SCAN:
      tcp->th_flags = TH_ACK;
      break;

   case NULL_SCAN:
      tcp->th_flags = 0x00;
      break;

   case FIN_SCAN:
      tcp->th_flags = TH_FIN;
      break;

   case XMAS_SCAN:
      tcp->th_flags = (TH_FIN | TH_PUSH |TH_URG);
      break;
  }

  /* calculate TCP checksum */
  pseudo_header *pseudoHeader = (struct pseudo_header *) (buffer + sizeof(struct ip) + sizeof(struct tcphdr));

  pseudoHeader->src = ip->ip_src.s_addr;
  pseudoHeader->dst = ip->ip_dst.s_addr;
  pseudoHeader->mbz = 0;
  pseudoHeader->proto = IPPROTO_TCP;
  pseudoHeader->len = ntohs(sizeof(struct tcphdr));							

  tcp->th_sum = calculateChecksum((unsigned short *)tcp, sizeof(struct pseudo_header) + sizeof(struct tcphdr));
  
  int one = 1;
  const int *value = &one;
  
  rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if(rawSocket < 0) {
    perror("Error");
    exit(0);
  }
  
  sin.sin_family = AF_INET;
  //inet_pton(AF_INET, job.destIp, &sin.sin_addr);
  sin.sin_addr.s_addr = ip->ip_dst.s_addr;
  
  result = setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL, value, sizeof(one));
  if(result < 0) {
    perror("Error");
    exit(0);
    //cout << "Warning: Cannot set HDRINCL for port: " << job.destinationPort << endl;
  }

  struct pcap_pkthdr packetHeader;
  //cout << "Before pcap_next " << endl;
  //pcap_breakloop(handle);
  const u_char *packet;
  int tries = 0;
  do {
    result = sendto(rawSocket, buffer, ip->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    if(result < 0) {
      //cout << "Error sending packet to port: " << job.destinationPort << endl;
      perror("Error");
      exit(0);
    }
    sleep(3);
    packet = pcap_next(handle, &packetHeader);
    tries++;
    //cout << "Try: " << tries << endl << endl;
  } while(packet == NULL && tries < 4);

  JobResult jobResult;
  strncpy(jobResult.destIp, job.destIp, INET_ADDRSTRLEN);
  jobResult.destinationPort = job.destinationPort;
  jobResult.scanType = job.scanType;
  jobResult.portStatus = UNKNOWN;		// initially set portStatus to -1

  if(packet == NULL) {
    if(job.scanType == SYN_SCAN || job.scanType == ACK_SCAN)
      jobResult.portStatus = FILTERED;
      
    else if(job.scanType == NULL_SCAN || job.scanType == FIN_SCAN || job.scanType == XMAS_SCAN)
      jobResult.portStatus = OPENORFILTERED;
    //cout << "NULL packet for IP: " << job.destIp << " port: " << job.destinationPort << endl << endl;
  }
  
  else if(packet != NULL) {
    const struct ip *ip;
    const struct tcphdr *tcp;
    size_t ipSize;
    size_t tcpSize;
  
    //cout << "Inside processpacket" << endl;
  
    ip = (struct ip *) (packet + ETHERNET_FRAME_SIZE);
    ipSize = sizeof(struct ip);
    
    if(ip->ip_p == IPPROTO_TCP) {
      tcp = (struct tcphdr *) (packet + ETHERNET_FRAME_SIZE + ipSize);
      
      /*tcpSize = TH_OFF(tcp) * 4;
      if(tcpSize < 20) {
        cout << "Invalid TCP header length: " << tcpSize << endl;
        return;
      }*/

      switch(job.scanType) {

        case SYN_SCAN:
      		if(((tcp->th_flags & 0x02) == TH_SYN) && (tcp->th_flags & 0x10) == TH_ACK) {
        	  //serv = getservbyport ( htons((int)args), "tcp" );
	          //fprintf (stdout, "TCP port %d open , possible service: %s\n", args, serv->s_name);
  	          //cout << "TCP Port open: " << job.destinationPort << " of IP: " << job.destIp << endl << endl;
        	  // RST is sent by kernel automatically
        	  jobResult.portStatus = OPEN;
      		}

	        else if((tcp->th_flags & 0x02) == TH_SYN) {
  	          //cout << "TCP Port open: " << job.destinationPort << " of IP: " << job.destIp << endl << endl;
        	  jobResult.portStatus = OPEN;
      		}

		else if((tcp->th_flags & 0x04 ) == TH_RST) {
	          //fprintf (stdout, "TCP port %d closed\n", args ); too much info on screen
	          //cout << "TCP port closed: " << job.destinationPort << " of IP: " << job.destIp << endl << endl;
        	  jobResult.portStatus = CLOSED;
	        }
	        
	        break;
	        
	case ACK_SCAN:
		if((tcp->th_flags & 0x04 ) == TH_RST) {
		  //cout << "TCP port unfiltered: " << job.destinationPort << " of IP: " << job.destIp << endl << endl;
          	  jobResult.portStatus = UNFILTERED;
		}
		
		break;
		
	case NULL_SCAN:
		if((tcp->th_flags & 0x04 ) == TH_RST) {
		  //cout << "TCP port closed: " << job.destinationPort << " of IP: " << job.destIp << endl << endl;
        	  jobResult.portStatus = CLOSED;
		}
		
		break;
		
	case FIN_SCAN:
		if((tcp->th_flags & 0x04 ) == TH_RST) {
		  //cout << "TCP port closed: " << job.destinationPort << " of IP: " << job.destIp << endl << endl;
        	  jobResult.portStatus = CLOSED;
		}
		
		break;
		
	case XMAS_SCAN:
		if((tcp->th_flags & 0x04 ) == TH_RST) {
		  //cout << "TCP port closed: " << job.destinationPort << " of IP: " << job.destIp << endl << endl;
        	  jobResult.portStatus = CLOSED;
		}
		
		break;
      }
    }
    
    else if(ip->ip_p == IPPROTO_ICMP) {

      struct icmp *icmpHeader = (struct icmp*) (packet + ETHERNET_FRAME_SIZE + ipSize);
      struct ip *innerIp = (struct ip*) (packet + ETHERNET_FRAME_SIZE + ipSize + 8);
      struct tcphdr *innerTcp  = (struct tcphdr*) (packet + ETHERNET_FRAME_SIZE + ipSize + 8 + 20);
      
      int icmpCode = icmpHeader->icmp_code;
      int icmpType = icmpHeader->icmp_type;
      //cout << "Received ICMP packet with code: " << icmpCode << " type: " << icmpType << endl;
      
      if(icmpType == 3 && (icmpCode == 1 || icmpCode == 2 || icmpCode == 3 || icmpCode == 9 || icmpCode == 10 || icmpCode == 13)) {
        //cout << "TCP Port filtered: " << job.destinationPort << " of IP: " << job.destIp << endl << endl;
        jobResult.portStatus = FILTERED;
      }
    }
  }
  
  jobResults.push_back(jobResult);
  
  close(rawSocket);
  //pcap_close(handle);
  //free(packet);
  //pcap_freecode(&filter);

  //delete filterExpression;
  pthread_mutex_unlock(&tcpMutex);
}

void Scanner::runUDPScan(Job job) {
  pthread_mutex_lock(&udpMutex);
  int result;

  char buffer[4096];
  int rawSocket;
  struct sockaddr_in sin;
  struct ip *ip = (struct ip *) buffer;
  struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct ip));

  /* If DNS packet */
  if(job.destinationPort == 53) {
    
  }


  /* Packet */
  memset(buffer, 0, 4096);						// clear the buffer
  
  ip->ip_hl = 0x5;							// header length = 5
  ip->ip_v = 0x4;							// version = 4
  ip->ip_tos = 0x0;							// type of service
  ip->ip_len = sizeof(struct ip) + sizeof(struct udphdr);		// no payload
  ip->ip_id = htonl(12345);						// simple id
  ip->ip_off = 0x0;							// no fragmentation
  ip->ip_ttl = 225;							// time to live
  ip->ip_p = IPPROTO_UDP;						// protocol
  ip->ip_src.s_addr = inet_addr(localIpAddress);			// source - local ip 
  ip->ip_dst.s_addr = inet_addr(job.destIp);				// destination ip
  ip->ip_sum = calculateChecksum((unsigned short *)&ip, sizeof(ip));	// checksum

  udp->uh_sport = htons(2345);						// source port
  udp->uh_dport = htons(job.destinationPort);				// destination port
  udp->uh_ulen = ntohs(sizeof(struct udphdr));
  udp->uh_sum = 0;

  /* calculate UDP checksum */
  pseudo_header *pseudoHeader = (struct pseudo_header *) (buffer + sizeof(struct ip) + sizeof(struct udphdr));

  pseudoHeader->src = ip->ip_src.s_addr;
  pseudoHeader->dst = ip->ip_dst.s_addr;
  pseudoHeader->mbz = 0;
  pseudoHeader->proto = IPPROTO_UDP;
  pseudoHeader->len = ntohs(sizeof(struct udphdr));							

  udp->uh_sum = calculateChecksum((unsigned short *)udp, sizeof(struct pseudo_header) + sizeof(struct udphdr));
  
  int one = 1;
  const int *value = &one;
  
  rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if(rawSocket < 0) {
    perror("Error");
    exit(0);
  }
  
  sin.sin_family = AF_INET;
  //inet_pton(AF_INET, job.destIp, &sin.sin_addr);
  sin.sin_addr.s_addr = ip->ip_dst.s_addr;
  
  result = setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL, value, sizeof(one));
  if(result < 0) {
    perror("Error");
    exit(0);
    //cout << "Warning: Cannot set HDRINCL for port: " << job.destinationPort << endl;
  }

  result = sendto(rawSocket, buffer, ip->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
  if(result < 0) {
    //cout << "Error sending packet to port: " << job.destinationPort << endl;
    perror("Error");
    exit(0);
  }

  sleep(3);
  //cout << "After sleep" << endl;
  
  
  struct pcap_pkthdr packetHeader;
  const u_char *packet = pcap_next(handle, &packetHeader);
  
  JobResult jobResult;
  strncpy(jobResult.destIp, job.destIp, INET_ADDRSTRLEN);
  jobResult.destinationPort = job.destinationPort;
  jobResult.scanType = job.scanType;
  jobResult.portStatus = UNKNOWN;		// initially set portStatus to -1
  
  if(packet == NULL) {
    jobResult.portStatus = OPENORFILTERED;
    //cout << "NULL packet for port: " << job.destinationPort << endl << endl;
  }
  
  else if(packet != NULL) {
    const struct ip *ip;
    const struct tcphdr *tcp;
    size_t ipSize;
    size_t tcpSize;
  
    //cout << "Inside processpacket" << endl;
  
    ip = (struct ip *) (packet + ETHERNET_FRAME_SIZE);
    ipSize = sizeof(struct ip);
    
    if(ip->ip_p == IPPROTO_ICMP) {

      struct icmp *icmpHeader = (struct icmp*) (packet + ETHERNET_FRAME_SIZE + ipSize);
      struct ip *innerIp = (struct ip*) (packet + ETHERNET_FRAME_SIZE + ipSize + 8);
      struct udphdr *innerUdp  = (struct udphdr*) (packet + ETHERNET_FRAME_SIZE + ipSize + 8 + 20);
      
      int icmpCode = icmpHeader->icmp_code;
      int icmpType = icmpHeader->icmp_type;
      //cout << "Received ICMP packet with code: " << icmpCode << " type: " << icmpType << endl;
      
      if(icmpType == 3 && (icmpCode == 3)) {
        //cout << "UDP Port closed: " << job.destinationPort << " of IP: " << job.destIp << endl << endl;
        jobResult.portStatus = CLOSED;
      }
      
      else if(icmpType == 3 && (icmpCode == 1 || icmpCode == 2 || icmpCode == 9 || icmpCode == 10 || icmpCode == 13)) {
        //cout << "UDP Port filtered: " << job.destinationPort << " of IP: " << job.destIp << endl << endl;
        jobResult.portStatus = FILTERED;
      }
    }
    
    else if(ip->ip_p == IPPROTO_UDP) {
      //cout << "Received UDP response" << " from IP: " << job.destIp << " port: " << job.destinationPort << endl << endl;
      jobResult.portStatus = OPEN;
    }
    
    else {
      //cout << "Received response for UDP packet" << " from IP: " << job.destIp << " port: " << job.destinationPort << endl << endl;
      jobResult.portStatus = OPEN;
    }
  }

  jobResults.push_back(jobResult);

  close(rawSocket);
  //pcap_close(handle);
  //free(packet);
  //pcap_freecode(&filter);
  
  //delete filterExpression;
  pthread_mutex_unlock(&udpMutex);
}

void Scanner::initializePcapHandle(ps_args_t *ps_args) {
  // referenced from http://sock-raw.org/papers/syn_scanner
  struct bpf_program filter;
  char *filterExpression;
  char errbuf[PCAP_ERRBUF_SIZE];		// buffer to hold libpcap errors
  int result;

  filterExpression = new char[256];
  memset(filterExpression, 0, 256);
  
  for(int i = 0; i < ps_args->ipAddressList.size(); i++) {
    const char *ipAddr = ps_args->ipAddressList[i].c_str();
    //cout << ipAddr << endl;
    sprintf(filterExpression + strlen(filterExpression), "src host %s", ipAddr);
    if(i < ps_args->ipAddressList.size() - 1) {
      sprintf(filterExpression + strlen(filterExpression), " || ");
    }
  }
  
  //cout << "Filter Expression: " << endl << filterExpression << endl;
  
  handle = pcap_open_live(dev, BUFF, 0, 0, errbuf);
  if(handle == NULL) {
    cout << "Error opening device " << dev << ". Error " << errbuf << endl;
    exit(0);
  }
  
  result = pcap_setnonblock(handle, 1, errbuf);
  if(result == -1) {
    cout << "Error setting nonblocking mode " << pcap_geterr(handle) << endl;
    exit(0);
  }
  
  result = pcap_compile(handle, &filter, filterExpression, 0, 0);
  if(result == -1) {
    cout << "Error compiling filter " << pcap_geterr(handle) << endl;
    exit(0);
  }
  
  result = pcap_setfilter(handle, &filter);
  if(result == -1) {
    cout << "Error applying filter " << pcap_geterr(handle) << endl;
    exit(0);
  }
}

void Scanner::printResult() {
  int resultSize = jobResults.size();
  cout << "Completed total " << resultSize << " jobs" << endl;
  
  cout << "IP Address\t" << "Port\t" << "SCAN Type\t" << "Status" << endl;
  cout << "-----------------------------------------------" << endl;
  for(int i = 0; i < resultSize; i++) {
    JobResult jobResult = jobResults[i];
    cout << jobResult.destIp << "\t" << jobResult.destinationPort << "\t";
    
    switch(jobResult.scanType) {
      case SYN_SCAN:
        cout << "SYN Scan\t";
        break;
        
      case ACK_SCAN:
        cout << "ACK Scan\t";
        break;
        
      case NULL_SCAN:
        cout << "NULL Scan\t";
        break;
        
      case FIN_SCAN:
        cout << "FIN Scan\t";
        break;
        
      case XMAS_SCAN:
        cout << "XMAS Scan\t";
        break;
        
      case UDP_SCAN:
        cout << "UDP Scan\t";
        break;
    }
    
    switch(jobResult.portStatus) {
      case OPEN:
        cout << "Open" << endl;
        break;

      case CLOSED:
        cout << "Closed" << endl;
        break;

      case FILTERED:
        cout << "Filtered" << endl;
        break;

      case UNFILTERED:
        cout << "Unfiltered" << endl;
        break;

      case OPENORFILTERED:
        cout << "Open | Filtered" << endl;
        break;
    }
  }
}

Scanner::~Scanner() {
  // destructor
  if(numberOfThreads > 0) {
    pthread_mutex_destroy(&getJobMutex);
    pthread_mutex_destroy(&udpMutex);
    pthread_mutex_destroy(&tcpMutex);
  }
  pcap_close(handle);
  delete localIpAddress;
}
