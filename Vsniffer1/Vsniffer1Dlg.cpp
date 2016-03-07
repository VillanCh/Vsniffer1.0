
// Vsniffer1Dlg.cpp : 实现文件
//

#include "stdafx.h"
#include "Vsniffer1.h"
#include "Vsniffer1Dlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CVsniffer1Dlg 对话框



CVsniffer1Dlg::CVsniffer1Dlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CVsniffer1Dlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CVsniffer1Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	//	DDX_Control(pDX, IDC_DEVICEINFO, Details);
	DDX_Control(pDX, IDC_DEVICE, devId);
	DDX_Control(pDX, IDC_TCP, m_tcp);
	DDX_Control(pDX, IDC_UDP, m_udp);
	DDX_Control(pDX, IDC_ICMP, m_icmp);
	DDX_Control(pDX, IDC_IP, m_ip);
	DDX_Control(pDX, IDC_ARP, m_arp);
}

BEGIN_MESSAGE_MAP(CVsniffer1Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
//	ON_LBN_SELCHANGE(IDC_LIST1, &CVsniffer1Dlg::OnLbnSelchangeList1)
	ON_BN_CLICKED(IDC_START, &CVsniffer1Dlg::OnBnClickedStart)
	ON_BN_CLICKED(IDC_GETDEVICE, &CVsniffer1Dlg::OnBnClickedGetdevice)
	ON_BN_CLICKED(IDC_COUNT, &CVsniffer1Dlg::OnBnClickedCount)
	ON_BN_CLICKED(IDC_UPDATE, &CVsniffer1Dlg::OnBnClickedUpdate)
	ON_BN_CLICKED(IDC_BUTTON5, &CVsniffer1Dlg::OnBnClickedButton5)
END_MESSAGE_MAP()


// CVsniffer1Dlg 消息处理程序

BOOL CVsniffer1Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
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

	// TODO:  在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CVsniffer1Dlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CVsniffer1Dlg::OnPaint()
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
HCURSOR CVsniffer1Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CVsniffer1Dlg::OnLbnSelchangeList1()
{
	// TODO:  在此添加控件通知处理程序代码
}


void CVsniffer1Dlg::OnBnClickedStart()
{
	// TODO:  在此添加控件通知处理程序代码
	CString id = CString("");
	devId.GetWindowTextW(id);

	if (id == CString(""))
	{
		MessageBoxW(CString("请输入正确的设备编号或者先获取设备"), CString("ERROR"), 0);
		return;
	}

	DevId=_ttoi(id);
	//id.Format(_T("%d"),i);
	//dumper.init();
	//dumper.startCapture(false, NULL);
	//CreateThread();
	if (DevId == 0)
	{
		MessageBoxW(CString("请输入正确的设备编号或先获取设备"), CString("ERROR"), 0);
		return;
	}

	if (!(DevId>0 && DevId < this->dev_num))
	{
		MessageBoxW(CString("请输入正确的设备编号"), CString("ERROR"), 0);
		return;
	}
	dumper =new Dumper(this->deviceop.mapdevs[DevId]);
	AfxBeginThread(BeginDumper,this);
	this->startSniff = true;
}
UINT CVsniffer1Dlg::BeginDumper(void* param)
{
	CVsniffer1Dlg* ret = (CVsniffer1Dlg*)param;
	ret->dumper->init();
	ret->dumper->startCapture(false, NULL);
	return 0;
}

void CVsniffer1Dlg::OnBnClickedGetdevice()
{
	// TODO:  在此添加控件通知处理程序代码
	CString ret = deviceop.showDevices();
	this->dev_num = deviceop.dev_num;
	//CString detail = CString(ret);
	GetDlgItem(IDC_STATIC)->SetWindowTextW(ret);
	
}


void CVsniffer1Dlg::OnBnClickedCount()
{
	// TODO:  在此添加控件通知处理程序代码
	/*
	int tcp = 0;
	int udp = 0;
	int icmp = 0;
	int ip = 0;
	int arp = 0;

	*/
	if (this->startSniff != true)
	{
		MessageBox(CString("请先点击START再开始流量统计"),CString("ERROR"),0);
		return;
	}

	this->autoupdate = true;

	CString tmp;
	int b = this->dumper->tcp;
	tmp.Format(_T("%d"), b);
	m_tcp.SetWindowTextW(tmp);
	b = this->dumper->udp;
	tmp.Format(_T("%d"), b);
	m_udp.SetWindowTextW(tmp);	
	b = this->dumper->icmp;
	tmp.Format(_T("%d"), b);
	m_icmp.SetWindowTextW(tmp);	
	b = this->dumper->ip;
	tmp.Format(_T("%d"), b);
	m_ip.SetWindowTextW(tmp);	
	b = this->dumper->arp;
	tmp.Format(_T("%d"), b);
	m_arp.SetWindowTextW(tmp);
	
}


void CVsniffer1Dlg::OnBnClickedUpdate()
{
	// TODO:  在此添加控件通知处理程序代码
	if (this->startSniff != true)
	{
		MessageBox(CString("请先点击START再开始流量统计"), CString("ERROR"), 0);
		return;
	}

	this->autoupdate = true;
	AfxBeginThread(UpdateResult, this);
}
UINT CVsniffer1Dlg::UpdateResult(void *param)
{
	CVsniffer1Dlg *ret = (CVsniffer1Dlg*)param;
	CString tmp;
	
	while (ret->autoupdate)
	{
		Sleep(200);
		int b = ret->dumper->tcp;
		tmp.Format(_T("%d"), b);
		ret->m_tcp.SetWindowTextW(tmp);
		b = ret->dumper->udp;
		tmp.Format(_T("%d"), b);
		ret->m_udp.SetWindowTextW(tmp);
		b = ret->dumper->icmp;
		tmp.Format(_T("%d"), b);
		ret->m_icmp.SetWindowTextW(tmp);
		b = ret->dumper->ip;
		tmp.Format(_T("%d"), b);
		ret->m_ip.SetWindowTextW(tmp);
		b = ret->dumper->arp;
		tmp.Format(_T("%d"), b);
		ret->m_arp.SetWindowTextW(tmp);
	}
	return 0;
}


void CVsniffer1Dlg::OnBnClickedButton5()
{
	// TODO:  在此添加控件通知处理程序代码
	this->autoupdate = false;
}
