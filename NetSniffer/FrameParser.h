#pragma once
/*
����WinPcak���񵽵�frame
����֡��������
*/


//  WinPcap 
#include "stdafx.h"
#include "FrameDef.h"
#include "pcap.h"
#include "winsock2.h"
#include "vector"
using namespace std;

/* ���ܲ��񵽵� char* data ����֡���ݣ����н����� ���Ի��ͳ�����ݣ��͸���Э��ͷ��ָ�룬�ֱ����
	pktCount �� header_Pack��
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
	// ��ȡָ��idx�����ݰ�
	const pair<pktCount, headerPack>& getAt(int idx);
	pktCount getStatistics();
	headerPack getParsedHeaderPack();
	vector<pair<pktCount, headerPack>> getParesSet();

private:
	// ����
	const u_char* m_pkt_data;
	const PKTHDR* m_pacp_header;
	// �������
	pktCount m_pkt_counter;
	headerPack m_hdr_pack;
	// ÿ�ν����õ������ݶ����浽����
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
