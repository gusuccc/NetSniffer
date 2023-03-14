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
		//return m_adapterName2dev[adpName];
		auto iter = m_adapterName2dev.find(adpName);
		//std::cout << std::string(iter->second->description) << "IN adpName2dev" << std::endl;
		return iter->second;
	}
	return nullptr;
}

void SnifferGrab::setChoosedIf(pcap_if_t* dev)
{
	m_dev = dev;
}
