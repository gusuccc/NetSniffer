
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
	// 抓包分析类（Core)
	SnifferGrab m_snifferGrab;
	void UpdateGui(const pktCount* npkt, const datapkt* hdrspack);
	afx_msg void OnCbnSelchangeCombo1();// 网卡下拉框
	afx_msg void OnBnClickedButton1(); // 开始抓包

// 界面数据更新相关
private:
	void updateNPacket(const pktCount* npkt);// 更新统计数据
	void update_listCtrl(const pktCount* npkt, const datapkt* hdrsPack);// 更新数据帧列表
	void updateTree(int index, const pktCount* npkt, const datapkt* hdrsPack);// 更新树状分析表
	void updateEdit(datapkt* hdrsPack);// 更新帧内内容列表
	void update_listCtrl_change(int npkt, const datapkt* hdrsPack);// 按规则筛选
public:
// 网卡下拉列表
	CComboBox m_comboBox;
// 统计数据
	CEdit m_editTCP;
	CEdit m_editUDP;
	CEdit m_editICMP;
	CEdit m_editHTTP;
	CEdit m_editARP;
	CEdit m_editICMPv6;
	CEdit m_editIPv4;
	CEdit m_editIPv6;
	CEdit m_editOther;
	CEdit m_editSum;
// 数据包列表
	CListCtrl m_listCtrl;
// 树状分析
	CTreeCtrl m_treeCtrl;
// 数据包详情
	CEdit m_edit;
// 开始，结束，保存，读取，筛选，暂停/继续
	CButton m_buttonStart;
	CButton m_buttonStop;
	CButton m_buttonSave;
	CButton m_buttonRead;
	CButton m_buttonSift;
	//CButton m_ButtonPause;
//规则过滤列表
	CComboBox m_comboBoxRule;
	CEdit m_EditRule;
// 消息响应函数
	afx_msg void OnCbnSelchangeCombo2();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButton5();
	afx_msg void OnTvnSelchangedTree1(NMHDR* pNMHDR, LRESULT* pResult);//多余添加，无实际执行
	afx_msg void OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnNMCustomdrawList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedButton4();
	afx_msg void OnBnClickedButton6();
	afx_msg void OnEnChangeEdit12();
	//afx_msg void OnBnClickedButton7();
};
