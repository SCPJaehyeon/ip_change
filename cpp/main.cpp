#include "header/header.h"
using namespace std;

int main(int argc, char** argv){
    if(argc != 2){
        Usage(argv);
        return -1;
    }
    set_iptables();
    start_capture(argv);
    return 0;
}

