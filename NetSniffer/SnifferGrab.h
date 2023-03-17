#pragma once
#include "pcap.h"
#include "remote-ext.h" // ����wpcap��
#include "string"
#include "unordered_map"
#include "FrameDef.h"
#include "FrameParser.h"


class CNetSnifferDlg;//��ֹsnifferGrab.h �� NetSnifferDlg.h ���ֵ��໥������ѭ����������
class SnifferGrab
{
public:
	// device init �豸��ʼ��
	SnifferGrab(CNetSnifferDlg* this_of_gui);

	~SnifferGrab();
	int snif_initCap();// ��ʼ��ץ��
	int snif_setupFilter();// ��ʼ��������

	// �����б�
	int snif_startCap(); // ��ʼץ��

	// ������أ�
	pcap_if_t* getAvaliableDevs() const;// ��ȡ�����豸���������б�
	pcap_if_t* getChoosedIf() const;// ��ȡѡ�������豸��������
	pcap_if_t* adapterName2dev(const std::string adpName) const;

	// ץ�����
	void setChoosedIf(pcap_if_t* dev); //���ýӿ�ѡ��
	void setnpkt(int n); // �������ݰ�����
	int getnpkt() const; //��ȡ���ݰ�����
	pcap_t* getOpenedIfHandle() const; // ��ȡҪ����Ľӿ�
	void setOpenIfHandle(pcap_t* opend); //����Ҫ����Ľӿ�
	HANDLE getThreadHandle(); // ��ȡ�����߳�
	void  SnifferGrab::setThreadHandle(HANDLE thread_handle);// ���ô����߳�
	void setChoosedRule(string rule); //���ù��˹���
	string getChoosedRule(); //��ȡ���˹���
	int m_snif_CreateCapThread();  // �½�ץ���߳�

	//�ļ�ת�����
	pcap_dumper_t* getDumper() const;//��ȡת������
	const char* getDefaltDumpFilePath() const;

private:
	//����˽�к����������ڹ��ܺ�������ץ������
	static DWORD WINAPI m_snif_CapThreadFun(LPVOID lpParameter);  // �̴߳����� static����û��ָ����ʽ�ش��ݸ�����

	// ��GUI��������
	void tellGuiToUpdate(const pktCount* nPacket, const headerPack* hdrPack);

private:

	//����

	// adapters �������
	pcap_if_t* m_alldevs; // all �����豸
	pcap_if_t* m_dev;     // currently choosed ѡ����
	std::string m_filter_rule; // ���˹���

	std::unordered_map<std::string, pcap_if_t*> m_adapterName2dev;

	// file dump related �ļ�ת�����
	std::string filepath;
	std::string filename;

	// Statistics ͳ�����
	int devCount = 0;
	int m_npkt = 0;

	// pointer to gui client ָ��gui�ͻ��˵�ָ��
	CNetSnifferDlg* m_pSniffDlg;

	// handles ���������ӿ�
	pcap_t* m_opened_if_handle;  // pcap opened live
	HANDLE m_threadHandle = NULL;  // capture thread

	// dump �洢 
	pcap_dumper_t* dumpfile;
	const char* default_dump_file = "./data_dump";

public:
	// ����֡����
	DataParser data_parser;
};

