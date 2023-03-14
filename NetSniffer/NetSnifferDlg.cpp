
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
}

BEGIN_MESSAGE_MAP(CNetSnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_CBN_SELCHANGE(IDC_COMBO1, &CNetSnifferDlg::OnCbnSelchangeCombo1)
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


	// TODO: 优化添加column的代码
	//m_listCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	//m_listCtrl.InsertColumn(0, _T("编号"), 2, 80); //1表示右，2表示中，3表示左
	//m_listCtrl.InsertColumn(1, _T("时间"), 2, 260);
	//m_listCtrl.InsertColumn(2, _T("长度"), 2, 90);
	//m_listCtrl.InsertColumn(3, _T("源MAC地址"), 2, 220);
	//m_listCtrl.InsertColumn(4, _T("目标MAC地址"), 2, 220);
	//m_listCtrl.InsertColumn(5, _T("协议"), 2, 90);
	//m_listCtrl.InsertColumn(6, _T("源IP地址"), 2, 220);
	//m_listCtrl.InsertColumn(7, _T("目标IP地址"), 2, 220);

	m_comboBox.AddString(_T("请选择一个网卡接口（必选）"));
	m_comboBox.SetCurSel(0);
	//m_comboBoxRule.AddString(_T("请选择过滤规则（可选）"));

	//m_comboBoxRule.SetCurSel(0);

	//m_comboBoxRule.AddString(_T("ether"));
	//m_comboBoxRule.AddString(_T("tr"));
	//m_comboBoxRule.AddString(_T("ip"));
	//m_comboBoxRule.AddString(_T("ip6"));
	//m_comboBoxRule.AddString(_T("arp"));
	//m_comboBoxRule.AddString(_T("rarp"));
	//m_comboBoxRule.AddString(_T("decnet"));
	//m_comboBoxRule.AddString(_T("tcp"));
	//m_comboBoxRule.AddString(_T("udp"));
	//m_comboBoxRule.AddString(_T("xxx"));

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
