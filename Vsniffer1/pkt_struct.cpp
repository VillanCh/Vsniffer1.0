#ifndef __PKT_STRUCT_H__
#define __PKT_STRUCT_H__
#include "winpcap_basic.h"

// 以太网协议格式的定义  
typedef struct ether_header {
	u_char ether_dhost[6];      // 目标地址  
	u_char ether_shost[6];      // 源地址  
	u_short ether_type;         // 以太网类型  
}ether_header;

// 用户保存4字节的IP地址  
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;


// 用于保存IPV4的首部  
typedef struct ip_header {
#ifdef WORDS_BIGENDIAN  
	u_char ip_version : 4, header_length : 4;
#else  
	u_char header_length : 4, ip_version : 4;
#endif  

	u_char ver_ihl;     // 版本以及首部长度，各4位  
	u_char tos;         // 服务质量  
	u_short tlen;       // 总长度  
	u_short identification;     // 身份识别  
	u_short offset;         // 分组偏移  
	u_char ttl;         // 生命周期  
	u_char proto;       // 协议类型  
	u_short checksum;       // 包头测验码  
	ip_address saddr;   // 源IP地址  
	ip_address daddr;   // 目的IP地址  
	u_int op_pad;       //可选 填充字段  
}ip_header;

// 保存TCP首部  
typedef struct tcp_header {
	u_short sport;
	u_short dport;
	u_int sequence;     // 序列码  
	u_int ack;                  // 回复码  

#ifdef WORDS_BIGENDIAN  
	u_char offset : 4, reserved : 4;        // 偏移 预留  
#else  
	u_char reserved : 4, offset : 4;        // 预留 偏移  
#endif  

	u_char flags;               // 标志  
	u_short windows;            // 窗口大小  
	u_short checksum;           // 校验和  
	u_short urgent_pointer;     // 紧急指针  
}tcp_header;

typedef struct udp_header {
	u_int32_t sport;            // 源端口  
	u_int32_t dport;            // 目标端口  
	u_int8_t zero;              // 保留位  
	u_int8_t proto;             // 协议标识  
	u_int16_t datalen;          // UDP数据长度  
}udp_header;

typedef struct icmp_header {
	u_int8_t type;              // ICMP类型  
	u_int8_t code;              // 代码  
	u_int16_t checksum;         // 校验和  
	u_int16_t identification;   // 标识  
	u_int16_t sequence;         // 序列号  
	u_int32_t init_time;        // 发起时间戳  
	u_int16_t recv_time;        // 接受时间戳  
	u_int16_t send_time;        // 传输时间戳  
}icmp_header;

typedef struct arp_header {
	u_int16_t arp_hardware_type;
	u_int16_t arp_protocol_type;
	u_int8_t arp_hardware_length;
	u_int8_t arp_protocol_length;
	u_int16_t arp_operation_code;
	u_int8_t arp_source_ethernet_address[6];
	u_int8_t arp_source_ip_address[4];
	u_int8_t arp_destination_ethernet_address[6];
	u_int8_t arp_destination_ip_address[4];
}arp_header;

#endif