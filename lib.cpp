#include "lib.h"
#include "setup.h"

int validateIP(string ipAddress) {
  struct sockaddr_in sa;
  //cout << ipAddress << endl;
  return (inet_pton(AF_INET, ipAddress.c_str(), &(sa.sin_addr)));
}

int validateScan(char *scanType) {
  string scan = scanType;
  if(scan == "SYN")
    return SYN_SCAN;
    
  else if(scan == "ACK")
    return ACK_SCAN;
    
  else if(scan == "NULL")
    return NULL_SCAN;
    
  else if(scan == "FIN")
    return FIN_SCAN;

  else if(scan == "XMAS")
    return XMAS_SCAN;
    
  else if(scan == "UDP")
    return UDP_SCAN;

  else return UNKNOWN_SCAN;
}

void separatePorts(char *portToken, ps_args_t * ps_args) {
  if((strstr(portToken, ",") == NULL) && (strstr(portToken, "-") == NULL)) {
    if(find(ps_args->portList.begin(), ps_args->portList.end(), atoi(portToken)) == ps_args->portList.end()) {
      ps_args->portList.push_back(atoi(portToken));
      //cout << "Pushed port: " << portToken << endl;
    }
  }
    
  else {
    char *lhs, *rhs;
    char *listBegin, *listEnd;
    int listStart, listFinish;
    
    if(strstr(portToken, ",") != NULL) {
      lhs = strtok_r(portToken, ",", &rhs);
      //cout << "LHS: " << lhs << endl;
      //cout << "RHS: " << rhs << endl;
    }
    
    else {
      lhs = portToken;
      rhs = NULL;
    }
    
    if(strstr(lhs, "-") != NULL) {
      listBegin = strtok_r(lhs, "-", &listEnd);
      //cout << "List begin: " << listBegin << endl;
      //cout << "List end: " << listEnd << endl;

      listStart = atoi(listBegin);
      listFinish = atoi(listEnd);
      
      //invalid port range
      if(listStart > listFinish) {
        cout << "Invalid port range" << endl;
        usage(stdout);
        exit(0);
      }
      
      for(int i = listStart; i <= listFinish; i++) {
        if(find(ps_args->portList.begin(), ps_args->portList.end(), i) == ps_args->portList.end()) {
          ps_args->portList.push_back(i);
          //cout << "Pushed port: " << i << endl;
        }
      }
    }
    
    else {
      //cout << "Pushed port in else: " << lhs << endl;
      if(find(ps_args->portList.begin(), ps_args->portList.end(), atoi(lhs)) == ps_args->portList.end()) {
        ps_args->portList.push_back(atoi(lhs));
        //cout << "Pushed port: " << portToken << endl;
      }
    }
    
    //sort(portList.begin(), portList.end());
    
    if(rhs != NULL) {
      //puts(rhs);
      separatePorts(rhs, ps_args);
    }
  }
}

void getLocalIp(char *ipAddress, char *dev) {

  //referenced from http://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
  int demoSocket, result;
  const char *demoIp = "8.8.8.8";
  int demoPort = 53;			// DNS port
  struct sockaddr_in server;
  struct sockaddr_in client;
  socklen_t clientLen;
  struct ifaddrs *ifAddrs;

  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr(demoIp);
  server.sin_port = htons(demoPort);
  
  demoSocket = socket(AF_INET, SOCK_DGRAM, 0);
  if(demoSocket == -1) {
    perror("Error");
    exit(0);
  }
  
  result = connect(demoSocket, (const struct sockaddr*) &server , sizeof(server));
  if(result == -1) {
    perror("Error");
    exit(0);
  }
 
  clientLen = sizeof(client);
  result = getsockname(demoSocket, (struct sockaddr*) &client, &clientLen);
  //ipAddress = new char[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &client.sin_addr, ipAddress, clientLen);
  //cout << "Ip address: " << ipAddress << endl;
 
  close(demoSocket);
  
  result = getifaddrs(&ifAddrs);
  if(result == 0) {
    while(ifAddrs != NULL) {
      struct sockaddr_in *client1 = (struct sockaddr_in *) ifAddrs->ifa_addr;
      if(strcmp(ipAddress, inet_ntoa(client1->sin_addr)) == 0) {
        //dev = new char[sizeof(ifAddrs->ifa_name)];
        strncpy(dev, ifAddrs->ifa_name, sizeof(ifAddrs->ifa_name));
        //cout << "Device name: " << dev << endl;
        break;
      }
      ifAddrs = ifAddrs->ifa_next;
    }
  }
}

bool isLocalhost(char *ipAddress) {
  if(strcmp(ipAddress, "127.0.0.1") == 0 || strcmp(ipAddress, "0.0.0.0") == 0)
    return true;
  return false;
}

unsigned short calculateChecksum(unsigned short *addr, int len) {
  register long sum;
  register short checksum;
 
  sum = 0;
  while(len > 1) {
    sum += *addr++;
    len -= 2;
  }

  if(len == 1) {
    sum += *(unsigned char *) addr;
  }
 
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  checksum = ~sum;

  return checksum;
}

void readIpFromFile(ps_args_t* ps_args, char *fileName) {
  ifstream ipFile(fileName);
  
  if(!ipFile) {
    cout << "Cannot open file" << endl;
    usage(stdout);
    exit(0);
  }
  
  char ipFromFile[20];
  while(ipFile >> ipFromFile) {
    //cout << "IP address: " << ipFromFile << endl;
    if(validateIP(ipFromFile) != 1) {
      cout << "Invalid IP address: " << ipFromFile;
    }
    
    else {
      if(!ps_args->fileFlag)
        ps_args->fileFlag = true;
      ps_args->ipAddressList.push_back(ipFromFile);
    }
  }
  
  ipFile.close();
}
