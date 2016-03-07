
// Vsniffer1Dlg.h : 头文件
//

#pragma once
#include "Dumper.h"
#include "DeviceOp.h"
#include "afxwin.h"

// CVsniffer1Dlg 对话框
class CVsniffer1Dlg : public CDialogEx
{
// 构造
public:
	CVsniffer1Dlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_VSNIFFER1_DIALOG };

	DeviceOp deviceop = DeviceOp();

	Dumper *dumper;
	int tcp = 0;
	int udp = 0;
	int icmp = 0;
	int ip = 0;
	int arp = 0;

	int dev_num = 0;

	int DevId;
	static UINT CVsniffer1Dlg::BeginDumper(void *param);
	static UINT CVsniffer1Dlg::UpdateResult(void *param);
	CString device_detail;
	bool startSniff = false;
	bool autoupdate = false;

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
	afx_msg void OnLbnSelchangeList1();
	afx_msg void OnBnClickedStart();
	afx_msg void OnBnClickedGetdevice();
	CEdit Details;
	CEdit devId;
	afx_msg void OnBnClickedCount();
	CStatic m_tcp;
	CStatic m_udp;
	CStatic m_icmp;
	CStatic m_ip;
	CStatic m_arp;
	afx_msg void OnBnClickedUpdate();
	afx_msg void OnBnClickedButton5();
};
