#pragma once
#include "pcap.h"
#include "remote-ext.h" // 包含wpcap库
#include "string"
#include "unordered_map"
#include "FrameDef.h"
#include "FrameParser.h"


class CNetSnifferDlg;//防止snifferGrab.h 和 NetSnifferDlg.h 出现的相互包含的循环依赖问题
class SnifferGrab
{
public:
	// device init 设备初始化
	SnifferGrab(CNetSnifferDlg* this_of_gui);

	~SnifferGrab();
	int snif_initCap();// 初始化抓包
	int snif_setupFilter();// 初始化过滤器

	// 函数列表
	int snif_startCap(); // 开始抓包

	// 网卡相关，
	pcap_if_t* getAvaliableDevs() const;// 获取网络设备（网卡）列表
	pcap_if_t* getChoosedIf() const;// 获取选中网络设备（网卡）
	pcap_if_t* adapterName2dev(const std::string adpName) const;

	// 抓包相关
	void setChoosedIf(pcap_if_t* dev); //设置接口选择
	void setnpkt(int n); // 设置数据包个数
	int getnpkt() const; //获取数据包个数
	pcap_t* getOpenedIfHandle() const; // 获取要处理的接口
	void setOpenIfHandle(pcap_t* opend); //设置要处理的接口
	HANDLE getThreadHandle(); // 获取处理线程
	void  SnifferGrab::setThreadHandle(HANDLE thread_handle);// 设置处理线程
	void setChoosedRule(string rule); //设置过滤规则
	string getChoosedRule(); //获取过滤规则
	int m_snif_CreateCapThread();  // 新建抓包线程

	//文件转储相关
	pcap_dumper_t* getDumper() const;//获取转储程序
	const char* getDefaltDumpFilePath() const;

private:
	//类内私有函数，服务于功能函数创建抓包进程
	static DWORD WINAPI m_snif_CapThreadFun(LPVOID lpParameter);  // 线程处理函数 static表明没有指针隐式地传递给函数

	// 给GUI更新数据
	void tellGuiToUpdate(const pktCount* nPacket, const headerPack* hdrPack);

private:

	//变量

	// adapters 网卡相关
	pcap_if_t* m_alldevs; // all 所有设备
	pcap_if_t* m_dev;     // currently choosed 选择项
	std::string m_filter_rule; // 过滤规则

	std::unordered_map<std::string, pcap_if_t*> m_adapterName2dev;

	// file dump related 文件转储相关
	std::string filepath;
	std::string filename;

	// Statistics 统计相关
	int devCount = 0;
	int m_npkt = 0;

	// pointer to gui client 指向gui客户端的指针
	CNetSnifferDlg* m_pSniffDlg;

	// handles 处理网卡接口
	pcap_t* m_opened_if_handle;  // pcap opened live
	HANDLE m_threadHandle = NULL;  // capture thread

	// dump 存储 
	pcap_dumper_t* dumpfile;
	const char* default_dump_file = "./data_dump";

public:
	// 数据帧解析
	DataParser data_parser;
};

