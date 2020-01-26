#include "header/header.h"

int set_iptables(){
    system("iptables -F"); //iptables Reset
    system("iptables -t mangle -F");
    system("iptables -A OUTPUT -j NFQUEUE --queue-num 0"); //iptables Set
    system("iptables -t mangle -A PREROUTING -j NFQUEUE --queue-num 0");
    return 1;
}
