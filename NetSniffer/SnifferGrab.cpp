/*
* 抓包程序：功能：
* 1、获取网卡
* 2、查找数据帧
* 3、保存与读取
* 4、协议支持：IPv4、TCP、UDP、HTPP、ARP、ICMP
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
//#include "frame_parser.h"// 以太网数据解析器支持


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
	// 用来记录找到的网卡设备
	int devCount = 0;
	char* errbuff = new char[PCAP_ERRBUF_SIZE];
	//if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &m_alldevs, errbuff) == -1)
	if (pcap_findalldevs(&m_alldevs, errbuff) == -1)//调用pcap_findalldevs()获得网卡接口信息
	{
		int x = MessageBox(GetForegroundWindow(), _T("没有找到网卡设备，请确认Npcap-1.60驱动已经安装！"), _T("错误"), 2);
		if (x == 3) { // 终止
			PostMessage(NULL, WM_QUIT, 0, 0);
		}
		if (x == 4) { // 重试
			while (1) {
				x = MessageBox(GetForegroundWindow(), _T("没有找到网卡设备，请确认Npcap-1.60驱动已经安装！"), _T("错误"), 2);
				if (x != 4) break;
			}
			if (x == 3) {
				PostMessage(NULL, WM_QUIT, 0, 0);
			}
		}
	}

	for (auto dev = m_alldevs; dev; dev = dev->next) {
		printf("\n%d : 网卡名称: %s\n", ++devCount, dev->name);
		if (dev->description)
			printf("\t描述（%s）\n", dev->description);

		m_adapterName2dev[std::string(dev->description)] = dev;
	}

	if (devCount > 0) return devCount;
	return -1; // No adapter found
}

int SnifferGrab::snif_setupFilter()
{
	// 设置过滤器
	struct bpf_program fcode;
	auto curIf = this->getChoosedIf();
	int netmask;
	if (curIf->addresses != NULL)
		// 检索接口第一个地址的掩码
		netmask = ((struct sockaddr_in*)(curIf->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		// 如果接口没有地址，就假设它位于C类网络
		netmask = 0xffffff;
	// 获取规则
	auto tmp = this->getChoosedRule();
	
	if (pcap_compile(this->getOpenedIfHandle(), &fcode, const_cast<char*>(this->getChoosedRule().c_str()), 1, netmask) < 0)
	{
		MessageBox(GetForegroundWindow(), _T("无法编译过滤规则.请检查过滤规则语法"), _T("错误"), 1);
		//	printf("\nUnable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	// 报错提示
	if (pcap_setfilter(this->getOpenedIfHandle(), &fcode) < 0)
	{
		MessageBox(GetForegroundWindow(), _T("设置过滤规则时出现错误"), _T("提示"), 1);
		fprintf(stderr, "\nError setting the filter.\n");
		return -1;
	}
	return 0;
}

int SnifferGrab::snif_startCap()
{
	// 打开网卡、初始化过滤器
	pcap_if_t* curAdapter = this->getChoosedIf();
	if (curAdapter == NULL) {
		MessageBox(GetForegroundWindow(), _T("请先选择一个要监听的网卡接口"), _T("提示"), 1);
		return -1;
	}

	char* errbuf = new char[PCAP_ERRBUF_SIZE];
	if ((m_opened_if_handle = pcap_open_live(curAdapter->name,	// 设备名
		65536,	// 捕获数据包长度
		PCAP_OPENFLAG_PROMISCUOUS,	// 混杂模式
		1000,	// 超时设置
		errbuf)) == NULL)
	{	// 错误信息

		MessageBox(GetForegroundWindow(), _T("无法打开接口：") + CString(curAdapter->description)
			+ CString("\n错误详情：") + CString(errbuf), _T("错误"), 1);
		return -1;
	}

	if (pcap_datalink(m_opened_if_handle) != DLT_EN10MB) {
		MessageBox(GetForegroundWindow(), _T("仅支持监听以太网络，请更换其它接口进行监听！"), _T("提示"), 1);
		return -1;
	}

	// 根据过滤规则设置过滤器
	if (this->snif_setupFilter() != 0) {//过滤器规则出错
		return -1;
	}

	// 打开转储文件并将其与接口相关联
	dumpfile = pcap_dump_open(this->getOpenedIfHandle(), default_dump_file);

	// 新建抓包线程（在该线程里解析、统计等）
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

// 创建抓包线程
int SnifferGrab::m_snif_CreateCapThread()
{
	// 关闭旧的抓包线程
	if (m_threadHandle != NULL) {
		CloseHandle(m_threadHandle);
	}

	// 启动抓包线程
	LPDWORD threadCap = NULL;
	auto threadHandle = CreateThread(NULL, 0, m_snif_CapThreadFun, this, 0, threadCap);

	if (threadHandle == NULL) {
		int code = GetLastError();
		CString str;
		str.Format(_T("创建线程错误，代码为%d."), code);
		MessageBox(GetForegroundWindow(), str, _T("创建线程错误，错误代码%d."), 0);
		return -1;

	}
	//设置为当前处理线程
	this->setThreadHandle(threadHandle);

	return 0;
}

//线程创建函数
DWORD __stdcall SnifferGrab::m_snif_CapThreadFun(LPVOID lpParameter)
{
	// printf("Thread Function Called\n");
	SnifferGrab* _this = (SnifferGrab*)lpParameter;
	struct pcap_pkthdr* pkt_header;   // 由pcap添加的通用标题
	const u_char* pkt_data;

	int code = 0;
	DataParser _parser;
	_this->data_parser = _parser;
	_this->setnpkt(0);
	// 检索数据包
	while ((code = pcap_next_ex(_this->getOpenedIfHandle(), &pkt_header, &pkt_data)) >= 0) {
		// 将数据包保存在转储文件中
		if ((u_char*)_this->dumpfile != NULL)
			pcap_dump((u_char*)_this->dumpfile, pkt_header, pkt_data);

		// 超时时间
		if (code == 0) {
			continue;
		}

		// 数据解析
		_this->data_parser.set(pkt_header, pkt_data);
		_this->data_parser.parse();

		// 解析结果
		pktCount nPacket = _this->data_parser.getStatistics();
		headerPack hdrPack = _this->data_parser.getParsedHeaderPack();
		// 打印
	/*	cout << endl << "-------------------------------";
		printf("Name: %s\n Total:%d ", hdrPack.pktType, nPacket.n_sum);
		cout << endl << "-------------------------------" << endl;
		*/
		// 更新 GUI
		_this->tellGuiToUpdate(&nPacket, &hdrPack);

		// 包计数+1
		_this->setnpkt(_this->getnpkt() + 1);
	}

	// 恢复按钮状态
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
	if (rule == "请选择过滤规则（可选）") {
		this->m_filter_rule = "";
	}
	else
		this->m_filter_rule = rule;
}
