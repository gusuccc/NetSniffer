#pragma once
#include "pcap.h"
#include "remote-ext.h" // ����wpcap��
#include "string"
#include "unordered_map"
#include "FrameDef.h"
//#include "frame_parser.h"


class CNetSnifferDlg;//��ֹsnifferGrab.h �� NetSnifferDlg.h ���ֵ��໥������ѭ����������
class SnifferGrab
{
public:
	SnifferGrab(CNetSnifferDlg* this_of_gui);
	~SnifferGrab();
	int snif_initCap();
	int snif_setupFilter();
	// �����б�
	int snif_startCap();

	// �������
	pcap_if_t* getAvaliableDevs() const;
	pcap_if_t* getChoosedIf() const;
	pcap_if_t* adapterName2dev(const std::string adpName) const;
	void setChoosedIf(pcap_if_t* dev);

private:
	// adapters ����
	pcap_if_t* m_alldevs; // all
	pcap_if_t* m_dev;     // currently choosed ѡ����
	std::string m_filter_rule;

	std::unordered_map<std::string, pcap_if_t*> m_adapterName2dev;

	// file dump related
	std::string filepath;
	std::string filename;

	//Statistics
	int devCount = 0;
	int m_npkt = 0;

	//pointer to gui client
	CNetSnifferDlg* m_pSniffDlg;

	//struct pktcount m_npacket;

	// handles 
	pcap_t* m_opened_if_handle;  // pcap opened live
	HANDLE m_threadHandle = NULL;  // capture thread

	// dump 
	pcap_dumper_t* dumpfile;
	const char* default_dump_file = "./data_dump";
};

