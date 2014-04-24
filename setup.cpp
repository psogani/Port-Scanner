#include "setup.h"
#include "lib.h"

void usage(FILE * file){
  if(file == NULL){
    file = stdout;
  }
  
  fprintf(file,
  	  " Usage:\n"
          "./portScanner [option1 .... optionN]\n"
          "  --help \tPrint this help screen\n"
          "  --ports <ports to scan> \tExample: \"./portScanner --ports 1,2,3-5\"\n"
          "  --ip <IP address to scan> \tExample: \"./portScanner --ip 127.0.0.1\"\n"
          "  --prefix <IP prefix to scan> \tExample: \"./portScanner --prefix 127.143.151.123/24\"\n"
          "  --file <file name containing IP addresses to scan>   \tExample: \"./portScanner --file filename.txt\"\n"
          "  --speedup <parallel threads to use> \tExample: \"./portScanner --speedup 10\"\n"
          "  --scan <one or more scans> \tExample: \"./portScanner --scan SYN NULL FIN XMAS\"\n");
}

void parse_args(int argc,  char * argv[], ps_args_t * ps_args){

  char *tokenValue = NULL;
  //char *portFromToken = NULL;
  string argValue;
  
  /* Initially set IP flag, file flag & prefix flag to false */
  ps_args->ipFlag = false;
  ps_args->fileFlag = false;
  ps_args->prefixFlag = false;
  
  /* Set number of threads to 0 initially */
  ps_args->numberOfThreads = 0;

  for(int i = 1; i < argc; i++) {
    argValue = argv[i];
    if(argValue == "--help") {
      usage(stdout);
      exit(0);
    }
    
    else if(argValue == "--ports") {
      i++;
      if((tokenValue = strtok(argv[i], " ")) != NULL) {
        //cout << tokenValue << endl;
        // check if no port or invalid port is provided
        if(isdigit(tokenValue[0]) == 0) {
          cout << "Invalid port" << endl;
          usage(stdout);
          exit(0);
        }
      
        separatePorts(tokenValue, ps_args);

      }
    }
    
    else if(argValue == "--ip") {
      i++;
      if((tokenValue = strtok(argv[i], " ")) != NULL) {
        //cout << tokenValue << endl;
        
        int result = validateIP(tokenValue);
        //cout << result << endl;
        if(result != 1) {
          cout << "Invalid IP" << endl;
          usage(stdout);
          exit(0);
        }
        
        //strncpy(ps_args->destIp, tokenValue, INET_ADDRSTRLEN);
        ps_args->ipAddressList.push_back(tokenValue);
        ps_args->ipFlag = true;
        //cout << "IP Address: " << ps_args->destIp << endl;
      }
    }
    
    else if(argValue == "--prefix") {
      i++;
      char *prefixIP;
      char *mask;
      prefixIP = strtok_r(argv[i], "/", &mask);
      //cout << prefixIP << endl;
      //cout << mask << endl;
      int result = validateIP(prefixIP);
      if(result != 1) {
        cout << "Invalid subnet IP" << endl;
        usage(stdout);
        exit(0);
      }
      
      //validate mask
      if(atoi(mask) > 31 || atoi(mask) < 1) {
        cout << "Invalid subnet mask" << endl;
        usage(stdout);
        exit(0);
      }
      
      ps_args->prefixFlag = true;
    }
    
    else if(argValue == "--file") {
      i++;
      //cout << "Filename: " << argv[i] << endl;
      readIpFromFile(ps_args, argv[i]);
    }
    
    else if(argValue == "--speedup") {
      i++;
      ps_args->numberOfThreads = atoi(argv[i]);
      //cout << "Speedup threads: " << ps_args->numberOfThreads << endl;
    }
    
    else if(argValue == "--scan") {
      //cout << "Type of scans: " << endl;
      //cout << argv[++i] << endl;
      int j = i + 1;
      while(j < argc) {
        //cout << argv[j] << endl;
        if(strstr(argv[j], "--") != NULL) {
          //i--;
          //cout << "I-- " << i << endl;
          break;
        }
        
        //cout << validateScan(argv[j]) << endl;
        int scanResult = validateScan(argv[j]);
        if(scanResult != UNKNOWN_SCAN) {
          //cout << "Scan type pushed: " << scanResult << endl;
          ps_args->scanList.push_back(scanResult);
        }
        
        i++;
        j++;
        //cout << "I++ " << i << endl;
      }
      //cout << "Outside while" << endl;
      //i--;
      //cout << "I " << i << endl;
      //cout << "argc " << argc << endl;
    }
    
    else {
      cout << "Invalid option specified: " << argv[i] << endl;
      usage(stdout);
      exit(0);
    }
  }
}
