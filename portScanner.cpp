#include "setup.h"
#include "Scanner.h"
#include "lib.h"

int main(int argc, char *argv[]) {
  time_point start, end;
  clock_t startTime, endTime;
  double totalTime;
  startTime = clock();  // referenced from http://stackoverflow.com/questions/876901/calculating-execution-time-in-c

  ps_args_t ps_args;
  parse_args(argc, argv, &ps_args);  
  Scanner *scanner = Scanner::shared(&ps_args);

  scanner->createJobList(&ps_args);
  scanner->initializePcapHandle(&ps_args);
  scanner->handleThreads(&ps_args);
  
  endTime = clock();
  totalTime = (double) endTime - startTime;
  cout << "Scanning took " << (double) totalTime/CLOCKS_PER_SEC << " seconds" << endl;
  printf("Scanning took: %ld\n", totalTime/CLOCKS_PER_SEC);
  
  scanner->printResult();
  
  return 0;
}
