/*
* ץ�����򣺹��ܣ�
* 1����ȡ����
* 2����������֡
* 3���������ȡ
* 4��Э��֧�֣�IPv4��TCP��UDP��HTPP��ARP��ICMP
*/
#include "pch.h"
#include "SnifferGrab.h"
#include "stdafx.h"
#include "snifferGrab.h"
#include "winsock2.h"
#include "Winuser.h" // MESSAGE
#include "string"
#include "iostream"
#include "utils.h"
#include "FrameDef.h"
//#include "frame_parser.h"// ��̫�����ݽ�����֧��


#include "NetSnifferDlg.h" 
#include "winnt.h"

SnifferGrab::SnifferGrab(CNetSnifferDlg* this_of_gui) : m_pSniffDlg(this_of_gui), m_alldevs(NULL), m_dev(NULL), m_opened_if_handle(NULL)
{

}


SnifferGrab::~SnifferGrab()
{
	/* We don't need any more the device list. Free it */
	pcap_freealldevs(m_alldevs);
}

int SnifferGrab::snif_initCap() {
	// ������¼�ҵ��������豸
	int devCount = 0;
	char* errbuff = new char[PCAP_ERRBUF_SIZE];
	//if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &m_alldevs, errbuff) == -1)
	if (pcap_findalldevs(&m_alldevs, errbuff) == -1)//����pcap_findalldevs()��������ӿ���Ϣ
	{
		int x = MessageBox(GetForegroundWindow(), _T("û���ҵ������豸����ȷ��Npcap-1.60�����Ѿ���װ��"), _T("����"), 2);
		if (x == 3) { // ��ֹ
			PostMessage(NULL, WM_QUIT, 0, 0);
		}
		if (x == 4) { // ����
			while (1) {
				x = MessageBox(GetForegroundWindow(), _T("û���ҵ������豸����ȷ��Npcap-1.60�����Ѿ���װ��"), _T("����"), 2);
				if (x != 4) break;
			}
			if (x == 3) {
				PostMessage(NULL, WM_QUIT, 0, 0);
			}
		}
	}

	for (auto dev = m_alldevs; dev; dev = dev->next) {
		printf("\n%d : ��������: %s\n", ++devCount, dev->name);
		if (dev->description)
			printf("\t������%s��\n", dev->description);

		m_adapterName2dev[std::string(dev->description)] = dev;
	}

	if (devCount > 0) return devCount;
	return -1; // No adapter found
}

int SnifferGrab::snif_setupFilter()
{
	// ���ù�����
	struct bpf_program fcode;
	auto curIf = this->getChoosedIf();
	int netmask;
	if (curIf->addresses != NULL)
		// �����ӿڵ�һ����ַ������
		netmask = ((struct sockaddr_in*)(curIf->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		// ����ӿ�û�е�ַ���ͼ�����λ��C������
		netmask = 0xffffff;
	// ��ȡ����
	auto tmp = this->getChoosedRule();
	
	if (pcap_compile(this->getOpenedIfHandle(), &fcode, const_cast<char*>(this->getChoosedRule().c_str()), 1, netmask) < 0)
	{
		MessageBox(GetForegroundWindow(), _T("�޷�������˹���.������˹����﷨"), _T("����"), 1);
		//	printf("\nUnable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	// ������ʾ
	if (pcap_setfilter(this->getOpenedIfHandle(), &fcode) < 0)
	{
		MessageBox(GetForegroundWindow(), _T("���ù��˹���ʱ���ִ���"), _T("��ʾ"), 1);
		fprintf(stderr, "\nError setting the filter.\n");
		return -1;
	}
	return 0;
}

int SnifferGrab::snif_startCap()
{
	// ����������ʼ��������
	pcap_if_t* curAdapter = this->getChoosedIf();
	if (curAdapter == NULL) {
		MessageBox(GetForegroundWindow(), _T("����ѡ��һ��Ҫ�����������ӿ�"), _T("��ʾ"), 1);
		return -1;
	}

	char* errbuf = new char[PCAP_ERRBUF_SIZE];
	if ((m_opened_if_handle = pcap_open_live(curAdapter->name,	// �豸��
		65536,	// �������ݰ�����
		PCAP_OPENFLAG_PROMISCUOUS,	// ����ģʽ
		1000,	// ��ʱ����
		errbuf)) == NULL)
	{	// ������Ϣ

		MessageBox(GetForegroundWindow(), _T("�޷��򿪽ӿڣ�") + CString(curAdapter->description)
			+ CString("\n�������飺") + CString(errbuf), _T("����"), 1);
		return -1;
	}

	if (pcap_datalink(m_opened_if_handle) != DLT_EN10MB) {
		MessageBox(GetForegroundWindow(), _T("��֧�ּ�����̫���磬����������ӿڽ��м�����"), _T("��ʾ"), 1);
		return -1;
	}

	// ���ݹ��˹������ù�����
	if (this->snif_setupFilter() != 0) {//�������������
		return -1;
	}

	// ��ת���ļ���������ӿ������
	dumpfile = pcap_dump_open(this->getOpenedIfHandle(), default_dump_file);

	// �½�ץ���̣߳��ڸ��߳��������ͳ�Ƶȣ�
	return this->m_snif_CreateCapThread();
	return 0;
}

pcap_if_t* SnifferGrab::getAvaliableDevs() const
{
	return m_alldevs;
}

pcap_if_t* SnifferGrab::getChoosedIf() const
{
	return m_dev;
}

pcap_if_t* SnifferGrab::adapterName2dev(const std::string adpName) const
{
	if (m_adapterName2dev.find(adpName) != m_adapterName2dev.end()) {
		auto iter = m_adapterName2dev.find(adpName);
		return iter->second;
	}
	return nullptr;
}

void SnifferGrab::setChoosedIf(pcap_if_t* dev)
{
	m_dev = dev;
}

void SnifferGrab::setnpkt(int n)
{
	this->m_npkt = n;
}

int SnifferGrab::getnpkt() const
{
	if (this->m_npkt <= 0) return 1;
	return this->m_npkt;
}

pcap_t* SnifferGrab::getOpenedIfHandle() const
{
	return m_opened_if_handle;
}

void SnifferGrab::setOpenIfHandle(pcap_t* opend)
{
	m_opened_if_handle = opend;
}

HANDLE SnifferGrab::getThreadHandle()
{
	return m_threadHandle;
}

void SnifferGrab::setThreadHandle(HANDLE thread_handle)
{
	m_threadHandle = thread_handle;
}

string SnifferGrab::getChoosedRule()
{
	//return this->m_pSniffDlg->getFilterRule();
	return this->m_filter_rule;
}

// ����ץ���߳�
int SnifferGrab::m_snif_CreateCapThread()
{
	// �رվɵ�ץ���߳�
	if (m_threadHandle != NULL) {
		CloseHandle(m_threadHandle);
	}

	// ����ץ���߳�
	LPDWORD threadCap = NULL;
	auto threadHandle = CreateThread(NULL, 0, m_snif_CapThreadFun, this, 0, threadCap);

	if (threadHandle == NULL) {
		int code = GetLastError();
		CString str;
		str.Format(_T("�����̴߳��󣬴���Ϊ%d."), code);
		MessageBox(GetForegroundWindow(), str, _T("�����̴߳��󣬴������%d."), 0);
		return -1;

	}
	//����Ϊ��ǰ�����߳�
	this->setThreadHandle(threadHandle);

	return 0;
}

//�̴߳�������
DWORD __stdcall SnifferGrab::m_snif_CapThreadFun(LPVOID lpParameter)
{
	// printf("Thread Function Called\n");
	SnifferGrab* _this = (SnifferGrab*)lpParameter;
	struct pcap_pkthdr* pkt_header;   // ��pcap��ӵ�ͨ�ñ���
	const u_char* pkt_data;

	int code = 0;
	DataParser _parser;
	_this->data_parser = _parser;
	_this->setnpkt(0);
	// �������ݰ�
	while ((code = pcap_next_ex(_this->getOpenedIfHandle(), &pkt_header, &pkt_data)) >= 0) {
		// �����ݰ�������ת���ļ���
		if ((u_char*)_this->dumpfile != NULL)
			pcap_dump((u_char*)_this->dumpfile, pkt_header, pkt_data);

		// ��ʱʱ��
		if (code == 0) {
			continue;
		}

		// ���ݽ���
		_this->data_parser.set(pkt_header, pkt_data);
		_this->data_parser.parse();

		// �������
		pktCount nPacket = _this->data_parser.getStatistics();
		headerPack hdrPack = _this->data_parser.getParsedHeaderPack();
		// ��ӡ
	/*	cout << endl << "-------------------------------";
		printf("Name: %s\n Total:%d ", hdrPack.pktType, nPacket.n_sum);
		cout << endl << "-------------------------------" << endl;
		*/
		// ���� GUI
		_this->tellGuiToUpdate(&nPacket, &hdrPack);

		// ������+1
		_this->setnpkt(_this->getnpkt() + 1);
	}

	// �ָ���ť״̬
	_this->m_pSniffDlg->m_buttonRead.EnableWindow(TRUE);
	_this->m_pSniffDlg->m_buttonStart.EnableWindow(TRUE);
	_this->m_pSniffDlg->m_buttonSave.EnableWindow(TRUE);
	return 0;
}

void SnifferGrab::tellGuiToUpdate(const pktCount* nPacket, const headerPack* hdrPack)
{
	this->m_pSniffDlg->UpdateGui(nPacket, hdrPack);
}

void SnifferGrab::setChoosedRule(string rule)
{
	if (rule == "��ѡ����˹��򣨿�ѡ��") {
		this->m_filter_rule = "";
	}
	else
		this->m_filter_rule = rule;
}
