
// NetSnifferDlg.cpp: 实现文件
//
#include "pch.h"
#include "stdafx.h"
#include "NetSniffer.h"
#include "NetSnifferDlg.h"
#include "afxdialogex.h"
#include "windows.h"
#include "string"
#include "Winuser.h" // MESSAGE
// winCap Suport
#include "pcap.h"

#include "iostream"
#include "string"

# include "utils.h"
//#define _DEBUG

//#ifdef _DEBUG
//#define new DEBUG_NEW
//#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CNetSnifferDlg 对话框



CNetSnifferDlg::CNetSnifferDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_NETSNIFFER_DIALOG, pParent),m_snifferGrab(this)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CNetSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, m_comboBox);
	DDX_Control(pDX, IDC_EDIT2, m_editTCP);
	DDX_Control(pDX, IDC_EDIT5, m_editUDP);
	DDX_Control(pDX, IDC_EDIT3, m_editICMP);
	DDX_Control(pDX, IDC_EDIT6, m_editHTTP);
	DDX_Control(pDX, IDC_EDIT4, m_editARP);
	DDX_Control(pDX, IDC_EDIT7, m_editICMPv6);
	DDX_Control(pDX, IDC_EDIT8, m_editIPv4);
	DDX_Control(pDX, IDC_EDIT9, m_editIPv6);
	DDX_Control(pDX, IDC_EDIT10, m_editOther);
	DDX_Control(pDX, IDC_EDIT11, m_editSum);
	DDX_Control(pDX, IDC_LIST1, m_listCtrl);
	DDX_Control(pDX, IDC_TREE1, m_treeCtrl);
	DDX_Control(pDX, IDC_EDIT1, m_edit);
	DDX_Control(pDX, IDC_BUTTON1, m_buttonStart);
	DDX_Control(pDX, IDC_BUTTON2, m_buttonStop);
	DDX_Control(pDX, IDC_BUTTON3, m_buttonSave);
	DDX_Control(pDX, IDC_BUTTON4, m_buttonRead);
	DDX_Control(pDX, IDC_COMBO2, m_comboBoxRule);
}

BEGIN_MESSAGE_MAP(CNetSnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_CBN_SELCHANGE(IDC_COMBO1, &CNetSnifferDlg::OnCbnSelchangeCombo1)
	ON_BN_CLICKED(IDC_BUTTON1, &CNetSnifferDlg::OnBnClickedButton1)
	ON_CBN_SELCHANGE(IDC_COMBO2, &CNetSnifferDlg::OnCbnSelchangeCombo2)
END_MESSAGE_MAP()


// CNetSnifferDlg 消息处理程序

BOOL CNetSnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码


	// 初始化列表参数，设置表头
	m_listCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_listCtrl.InsertColumn(0, _T("编号"), 2, 80); //1表示右，2表示中，3表示左
	m_listCtrl.InsertColumn(1, _T("时间"), 2, 260);
	m_listCtrl.InsertColumn(2, _T("长度"), 2, 90);
	m_listCtrl.InsertColumn(3, _T("源MAC地址"), 2, 220);
	m_listCtrl.InsertColumn(4, _T("目标MAC地址"), 2, 220);
	m_listCtrl.InsertColumn(5, _T("协议"), 2, 90);
	m_listCtrl.InsertColumn(6, _T("源IP地址"), 2, 220);
	m_listCtrl.InsertColumn(7, _T("目标IP地址"), 2, 220);

	// 网卡列表初始化
	m_comboBox.AddString(_T("请选择一个网卡接口（必选）"));
	m_comboBox.SetCurSel(0);
	// 过滤规则列表初始化
	m_comboBoxRule.AddString(_T("请选择过滤规则（可选）"));
	m_comboBoxRule.SetCurSel(0);
	m_comboBoxRule.AddString(_T("ether"));
	m_comboBoxRule.AddString(_T("tr"));
	m_comboBoxRule.AddString(_T("ip"));
	m_comboBoxRule.AddString(_T("ip6"));
	m_comboBoxRule.AddString(_T("arp"));
	m_comboBoxRule.AddString(_T("rarp"));
	m_comboBoxRule.AddString(_T("decnet"));
	m_comboBoxRule.AddString(_T("tcp"));
	m_comboBoxRule.AddString(_T("udp"));
	m_comboBoxRule.AddString(_T("xxx"));

	//m_CMyEdit.setPrompt();

	////  fddi(ether), tr, ip, ip6, arp, rarp, decnet, tcp and udp

	//// 初始化设置“结束”和“保存”按钮不可用
	//m_buttonStop.EnableWindow(FALSE);
	//m_buttonSave.EnableWindow(FALSE);


	// 初始化网络适配器列表
	if (m_snifferGrab.snif_initCap() < 0) {
		return FALSE;
	}

	/*更新GUI中网络适配器列表*/

	for (auto dev = m_snifferGrab.getAvaliableDevs(); dev; dev = dev->next) {
		m_comboBox.AddString(CString(dev->description));
	}

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CNetSnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CNetSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CNetSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


// Gui界面数据更新, 被snifferCore主动调用
void CNetSnifferDlg::UpdateGui(const pktCount* npkt, const datapkt* hdrspack)
{
	this->update_listCtrl(npkt, hdrspack);
	this->updateNPacket(npkt);
}

//网卡下拉框
void CNetSnifferDlg::OnCbnSelchangeCombo1()
{
	// TODO: 在此添加控件通知处理程序代码
	int curSel = m_comboBox.GetCurSel();


	CString selText;
	m_comboBox.GetWindowText(selText);

	// 设置当前处理的dev
	auto curDev = m_snifferGrab.adapterName2dev(CString2string(selText));
	m_snifferGrab.setChoosedIf(curDev);

	if (m_snifferGrab.getChoosedIf()) {
		//assert(std::string(m_snifferCore.getChoosedIf()->description) == CString2string(selText));
		ASSERT(std::string(m_snifferGrab.getChoosedIf()->description) == CString2string(selText));
	}
}

// 开始抓包
void CNetSnifferDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	// 计数统计重置
	pktCount pktcnt;
	CNetSnifferDlg::updateNPacket(&pktcnt);


	// 列表Item重新计数
	m_listCtrl.DeleteAllItems();
	m_snifferGrab.setnpkt(1);
	int status = m_snifferGrab.snif_startCap();
	if (status == -1) {
		printf("Error in snif_startCap\n");
		return;
	}

	m_comboBox.EnableWindow(FALSE);
	m_comboBoxRule.EnableWindow(FALSE);
	m_buttonStart.EnableWindow(FALSE);
	m_buttonStop.EnableWindow(TRUE);
	m_buttonRead.EnableWindow(FALSE);
	m_buttonSave.EnableWindow(FALSE);
}

void CNetSnifferDlg::updateNPacket(const pktCount* npkt)
{
	CString buf;
	buf.Format(_T("%d"), npkt->n_sum);
	this->m_editSum.SetWindowText(buf);

	buf.Format(_T("%d"), npkt->n_arp);
	this->m_editARP.SetWindowText(buf);

	buf.Format(_T("%d"), npkt->n_http);
	this->m_editHTTP.SetWindowText(buf);

	buf.Format(_T("%d"), npkt->n_icmp);
	this->m_editICMP.SetWindowText(buf);

	buf.Format(_T("%d"), npkt->n_icmp6);
	this->m_editICMPv6.SetWindowText(buf);

	buf.Format(_T("%d"), npkt->n_ip);
	this->m_editIPv4.SetWindowText(buf);

	buf.Format(_T("%d"), npkt->n_ip6);
	this->m_editIPv6.SetWindowText(buf);

	buf.Format(_T("%d"), npkt->n_tcp);
	this->m_editTCP.SetWindowText(buf);

	buf.Format(_T("%d"), npkt->n_udp);
	this->m_editUDP.SetWindowText(buf);

	buf.Format(_T("%d"), npkt->n_other);
	this->m_editOther.SetWindowText(buf);
}

// 更新数据帧列表（中间大表格）
void CNetSnifferDlg::update_listCtrl(const pktCount* npkt, const datapkt* hdrsPack)
{
	char strbuf[32];
	CString num, ts, len, s_mac, d_mac, proto, s_ip, d_ip;
	u_char* mac_arr;
	num.Format(_T("%d"), m_snifferGrab.getnpkt());
	len.Format(_T("%d"), hdrsPack->pcaph->len);
	mac_arr = hdrsPack->ethh->s_mac;
	s_mac.Format(_T("%02x:%02x:%02x:%02x:%02x:%02x"), mac_arr[0], mac_arr[1], mac_arr[2], mac_arr[3], mac_arr[4], mac_arr[5]);
	mac_arr = hdrsPack->ethh->d_mac;
	d_mac.Format(_T("%02x:%02x:%02x:%02x:%02x:%02x"), mac_arr[0], mac_arr[1], mac_arr[2], mac_arr[3], mac_arr[4], mac_arr[5]);
	proto.Format(_T("%S"), hdrsPack->pktType);

	// ts
	/* convert the timestamp to readable format*/
	struct tm* ltime;
	time_t t = hdrsPack->pcaph->ts.tv_sec;
	ltime = localtime(&t);
	strftime(strbuf, sizeof(strbuf), "%Y/%m/%d %H:%M:%S", ltime);
	ts = CString(strbuf);
	//// ip
	auto code = ntohs(hdrsPack->ethh->proto);
	if (code == ETH_PROTOCOL_ARP) {
		s_ip.Format(_T("%d.%d.%d.%d"), hdrsPack->arph->saddr.byte1, hdrsPack->arph->saddr.byte2, hdrsPack->arph->saddr.byte3, hdrsPack->arph->saddr.byte4);
		d_ip.Format(_T("%d.%d.%d.%d"), hdrsPack->arph->daddr.byte1, hdrsPack->arph->daddr.byte2, hdrsPack->arph->daddr.byte3, hdrsPack->arph->daddr.byte4);
	}
	else if (code == ETH_PROTOCOL_IP) {
		struct in_addr ip;
		ip.S_un.S_addr = *((u_long*)(void*)(&hdrsPack->iph->saddr));
		s_ip = CString(inet_ntoa(ip));
		ip.S_un.S_addr = *((u_long*)(void*)(&hdrsPack->iph->daddr));
		d_ip = CString(inet_ntoa(ip));
	}
	else if (code == ETH_PROTOCOL_IPV6) {
		for (int i = 0; i < 7; i++) {
			s_ip.AppendFormat(_T("%02x:", hdrsPack->iph6->saddr[i]));
			d_ip.AppendFormat(_T("%02x:", hdrsPack->iph6->daddr[i]));
		}
		s_ip.AppendFormat(_T("%02x", hdrsPack->iph6->saddr[7]));
		d_ip.AppendFormat(_T("%02x", hdrsPack->iph6->daddr[7]));
	}
	// ListControl
	int nitem = m_listCtrl.InsertItem(m_snifferGrab.getnpkt(), num);
	m_listCtrl.SetItemText(nitem, 1, ts);
	m_listCtrl.SetItemText(nitem, 2, len);
	m_listCtrl.SetItemText(nitem, 3, s_mac);
	m_listCtrl.SetItemText(nitem, 4, d_mac);
	m_listCtrl.SetItemText(nitem, 5, proto);
	m_listCtrl.SetItemText(nitem, 6, s_ip);
	m_listCtrl.SetItemText(nitem, 7, d_ip);

}

// 过滤规则下拉框
void CNetSnifferDlg::OnCbnSelchangeCombo2()
{
	// TODO: 在此添加控件通知处理程序代码
	CString str_rule;
	//m_comboBox.GetWindowText(selText);
	m_comboBoxRule.GetWindowText(str_rule);
	// 设置当前处理的dev
	auto rule = CString2string(str_rule);
	auto curDev = m_snifferGrab.adapterName2dev(CString2string(str_rule));
	// 将选择结果传给后端
	m_snifferGrab.setChoosedIf(curDev);
	m_snifferGrab.setChoosedRule(rule);
	printf("CURRENT CHOOSED RULE: %s\n\n\n\n\n\n", rule.c_str());
//
}
