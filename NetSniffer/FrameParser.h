#pragma once
/*
解析WinPcak捕获到的frame
负责帧解析的类
*/


//  WinPcap 
#include "stdafx.h"
#include "FrameDef.h"
#include "pcap.h"
#include "winsock2.h"
#include "vector"
using namespace std;

/* 接受捕获到的 char* data 网络帧数据，进行解析， 可以获得统计数据，和各层协议头的指针，分别放入
	pktCount 和 header_Pack中
*/
class DataParser {
	typedef struct pcap_pkthdr PKTHDR;

public:
	DataParser();
	DataParser(const u_char* pkt_data, PKTHDR* pkt_header);

	int parse();
	void setPktHeader(const PKTHDR* new_pkthdr);
	void setPktdata(const u_char* new_pkt_data);
	void set(const PKTHDR* new_pkthdr, const u_char* new_pkt_data);
	// 获取指定idx的数据包
	const pair<pktCount, headerPack>& getAt(int idx);
	pktCount getStatistics();
	headerPack getParsedHeaderPack();
	vector<pair<pktCount, headerPack>> getParesSet();

private:
	// 输入
	const u_char* m_pkt_data;
	const PKTHDR* m_pacp_header;
	// 解析结果
	pktCount m_pkt_counter;
	headerPack m_hdr_pack;
	// 每次解析得到的数据都保存到数组
	vector<pair<pktCount, headerPack>> m_idx2data;

	// parse functions
	int parse_ip(const u_char* pkt);
	int parse_ipv6(const u_char* pkt);
	int parse_arp(const u_char* pkt);

	int parse_udp(const u_char* pkt);
	int parse_tcp(const u_char* pkt);
	int parse_icmp(const u_char* pkt);
	int parse_icmpv6(const u_char* pkt);

	int parse_http(const u_char* pkt);
};
