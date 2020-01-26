#include "header/header.h"
using namespace std;

static int cmp, new_ret;
static u_int32_t des_ip;
static u_char *new_data; //new packet

static struct flow origin_info; //for map
static map<flow, u_int32_t> flowm;
static map<flow, u_int32_t>::iterator flowmit;

int ip_change(unsigned char *data, int pay_len); //ip changer
void dump(unsigned char* buf, int size);
static u_int32_t print_pkt (struct nfq_data *tb);
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data); //return packet

int start_capture(char** argv){
    des_ip = inet_addr(argv[1]);
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    unuse(nh);
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, nullptr);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("Packet Received!\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);


    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}


int ip_change(unsigned char *data, int pay_len){ //packet check and changer
    cmp = 0;
    unuse(pay_len);
    u_int8_t myIP[4] ={172,30,1,54};
    int check_sip = memcmp(&data[SIP],&myIP,4);
    u_int32_t origin_ip;
    if(data[PROTO]==0x06 && check_sip ==0){
        memcpy(&origin_info.sip, &data[SIP],4);
        memcpy(&origin_ip, &data[DIP],4);
        memcpy(&origin_info.sport, &data[SPORT],2);
        memcpy(&origin_info.dport, &data[DPORT],2);
        memcpy(&new_data[DIP],&des_ip,4);
        memcpy(&origin_info.dip, &new_data[DIP],4); //changed DIP
        flowm.insert(make_pair(origin_info,origin_ip));
        cmp=1;
    }
    u_int64_t cmpsip, cmpdip;
    u_int16_t cmpsport, cmpdport;
    memcpy(&cmpsip, &data[SIP],4);
    memcpy(&cmpdip, &data[DIP],4);
    memcpy(&cmpsport, &data[SPORT],2);
    memcpy(&cmpdport, &data[DPORT],2);
    int check_frompxy = memcmp(&data[SIP],&des_ip,4);
    int check_tome = memcmp(&data[DIP],&myIP,4);
    if(data[PROTO]==0x06 && check_frompxy==0 && check_tome==0){
        for(flowmit = flowm.begin();flowmit != flowm.end();flowmit++){
            int cmp1 = memcmp(&cmpsip, &flowmit->first.dip, 4); //first flow
            int cmp2 = memcmp(&cmpdip, &flowmit->first.sip, 4);
            int cmp3 = memcmp(&cmpsport, &flowmit->first.dport, 2);
            int cmp4 = memcmp(&cmpdport, &flowmit->first.sport, 2);
            if(cmp1==0&&cmp2==0&&cmp3==0&&cmp4==0){
                memcpy(&new_data[SIP],&flowmit->second,4);
            }
        }
        cmp=1;
    }
    return cmp;
}

static u_int32_t print_pkt (struct nfq_data *tb) //return packet id
{
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    new_ret = nfq_get_payload(tb, &new_data); //new packet get payload ret
    cmp = ip_change(data, ret); //return cmp

    u_int16_t ipchecksum = ip_checksum(new_data); //check checksum
    u_int16_t tcpchecksum = tcp_checksum(new_data, new_ret);
    new_data[IPCHECKSUM] = (ipchecksum & 0xFF00)>>8;
    new_data[IPCHECKSUM+1] = ipchecksum & 0x00FF;
    new_data[TCPCHECKSUM] = (tcpchecksum & 0xFF00)>>8;
    new_data[TCPCHECKSUM+1] = tcpchecksum & 0x00FF;

    if (ret >= 0)
        printf("payload_len=%d ", ret);

    fputc('\n', stdout);

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data) //return packet
{
    unuse(nfmsg);
    unuse(data);
    u_int32_t id = print_pkt(nfa);
    printf("id = %d \n",id);
    printf("entering callback\n");
        if(cmp==1){
            printf("This is CHANGED packet\n");
            return nfq_set_verdict(qh, id, NF_ACCEPT, u_int32_t(new_ret), new_data);
        }
        else {
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
        }
}
