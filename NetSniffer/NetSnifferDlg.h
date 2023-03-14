
// NetSnifferDlg.h: 头文件
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"
#include "snifferGrab.h"
#include "functional"
#include "string"
//#include "myCEdit.h"
using namespace std;

// CNetSnifferDlg 对话框
class CNetSnifferDlg : public CDialogEx
{
// 构造
public:
	CNetSnifferDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_NETSNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	// 网卡下拉列表
	CComboBox m_comboBox;
	// 抓包分析类（Core)
	SnifferGrab m_snifferGrab;
	afx_msg void OnCbnSelchangeCombo1();
};
