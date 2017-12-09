
// MyMacroDlg.cpp : 구현 파일
//

#include "stdafx.h"
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include "EditControlMacro.h"
#include "MyMacroDlg.h"
#include "afxdialogex.h"
#include "randomstr.h"
#include <iomanip>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 응용 프로그램 정보에 사용되는 CAboutDlg 대화 상자입니다.

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

// 구현입니다.
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


// CMyMacroDlg 대화 상자



CMyMacroDlg::CMyMacroDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_EDITCONTROLMACRO_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMyMacroDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, mHEdit);
	DDX_Control(pDX, IDC_EDIT2, mHBtn);
	DDX_Control(pDX, IDC_EDIT1, mHEdit);
	DDX_Control(pDX, IDC_EDIT2, mHBtn);
}

BEGIN_MESSAGE_MAP(CMyMacroDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CMyMacroDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CMyMacroDlg::OnBnClickedCancel)
	ON_EN_CHANGE(IDC_EDIT1, &CMyMacroDlg::OnEnChangeEdit1)
	ON_EN_CHANGE(IDC_EDIT2, &CMyMacroDlg::OnEnChangeEdit2)
END_MESSAGE_MAP()


// CMyMacroDlg 메시지 처리기

BOOL CMyMacroDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 시스템 메뉴에 "정보..." 메뉴 항목을 추가합니다.
	
	// IDM_ABOUTBOX는 시스템 명령 범위에 있어야 합니다.
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

	// 이 대화 상자의 아이콘을 설정합니다.  응용 프로그램의 주 창이 대화 상자가 아닐 경우에는
	//  프레임워크가 이 작업을 자동으로 수행합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, FALSE);		// 작은 아이콘을 설정합니다.

	// TODO: 여기에 추가 초기화 작업을 추가합니다.

	return TRUE;  // 포커스를 컨트롤에 설정하지 않으면 TRUE를 반환합니다.
}

void CMyMacroDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

// 대화 상자에 최소화 단추를 추가할 경우 아이콘을 그리려면
//  아래 코드가 필요합니다.  문서/뷰 모델을 사용하는 MFC 응용 프로그램의 경우에는
//  프레임워크에서 이 작업을 자동으로 수행합니다.

void CMyMacroDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 그리기를 위한 디바이스 컨텍스트입니다.

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 클라이언트 사각형에서 아이콘을 가운데에 맞춥니다.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 아이콘을 그립니다.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// 사용자가 최소화된 창을 끄는 동안에 커서가 표시되도록 시스템에서
//  이 함수를 호출합니다.
HCURSOR CMyMacroDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CMyMacroDlg::OnBnClickedOk()
{
	CString str;
	HWND Hwnd = 0;
	HWND Hcon = 0;
	char buf[BUF_MAXSIZE] = { 0, };
	wchar_t errorbuf[256] = { 0, };

	// Get Windows Handle from Window_Edit EditControl
	mHEdit.GetWindowTextW(str);
	Hwnd = (HWND)wcstol(str, NULL, 16);
	// Get Context Handle from Context_Edit EditControl
	mHBtn.GetWindowTextW(str);
	Hcon = (HWND)wcstol(str, NULL, 16);
	
	if (Hwnd == 0 || Hcon == 0) return;

	// use boost::log for Logging
	boost::log::add_file_log
	(
		boost::log::keywords::file_name = "OppaGo_TV_%N.log",
		boost::log::keywords::rotation_size = 10 * 1024 * 1024,
		boost::log::keywords::time_based_rotation = boost::log::sinks::file::rotation_at_time_point(0, 0, 0),
		boost::log::keywords::format = "[%TimeStamp%]: %Message%"
		//(			
		//	boost::log::expressions::stream
		//	<< std::hex << std::setw(8) << std::setfill('0')
		//	<< boost::log::expressions::attr< unsigned int >("LineID")
		//	<< "\t"
		//	<< boost::log::expressions::format_date_time<boost::posix_time::ptime>("TimeStamp","%Y-%m-%d %H:%M:%S")
		//	<< "\t:\t[" << boost::log::expressions::smessage
		//	<< "]" << "%Message%"
		//)
	);
	boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::info);

	GenRandomString((uint8*)buf, BUF_MAXSIZE-1);
	SendMessageA(Hwnd, CB_ADDSTRING, 0, (WPARAM)"123456");
	Sleep(500);
	SendMessageA(Hwnd, WM_SETTEXT, 0, (WPARAM)"Test123");
	Sleep(500);
	SendMessageA(Hwnd, CB_SELECTSTRING, -1, (WPARAM)"123456");
	Sleep(500);
	SendMessageA(Hcon, BM_CLICK, 0, 0);
	Sleep(500);
	//SendMessageA(Hcon, WM_LBUTTONDOWN, 0, 1);
	//SendMessageA(Hcon, WM_LBUTTONUP, 0, 1);
	//SendMessageA((HWND)0x804ba, WM_COMMAND, NULL, MAKELONG(Hcon, BN_CLICKED));

	// Logging
	BOOST_LOG_TRIVIAL(info) << buf;
}


void CMyMacroDlg::OnBnClickedCancel()
{
	MessageBox(TEXT("Bye~"));
	CDialogEx::OnCancel();
}


void CMyMacroDlg::OnEnChangeEdit1()
{
}


void CMyMacroDlg::OnEnChangeEdit2()
{
}
