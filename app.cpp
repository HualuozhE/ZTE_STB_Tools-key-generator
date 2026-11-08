// app.cpp - ZTE STB Tools 一键算号机（MFC 静态编译对话框程序）
//
// 布局：机器特征码编辑框 / 一键算号按钮 / 两个注册码编辑框(2.1.1-8.1.1 通用 与
// 2.0.0，各配复制按钮) / 红字流水线日志。
// 功能：粘贴机器特征码 → 一键算号 → 同时生成两个已知版本的注册码，
//       2.1.1/8.1.1 通用版自动置入剪贴板，另一版本可用复制按钮复制。
// 隐藏自检：以 --selftest 参数启动时，用验收样例自校验并写出结果文件。
#include <afxwin.h>
#include <afxext.h>
#include "resource.h"
#include "KeyGen.h"

// ---------- 验收样例（正确示例文件中的机器码与注册码） ----------
static const wchar_t* MC_REF =
L"sq1478000129000000234800001443EF6A00000000610A48D126F8D524D8B2D18C99F9C7AF"
L"3A2E090603021A238F46F95068E23F88C4BA8F71FD35124418776DEB1CA5EB847662D5872C431E21"
L"8D8F9253667FBC5DD3ADA4B18C871DA1D3ADA4B18C871DA1D3ADA4B18C871DA1D3ADA4B18C871DA1"
L"D3ADA4B18C871DA1D3ADA4B18C871DA1EC6E9511F99A6534";

static const char* REG_REF =
"800001D62C0000AE7200003333333333333333"
"689A51FF4044F8A6848360264DD650A69B047262BF4A6550672BCFDDCD1CEA82"
"65571D124E4D2C79D53BFC6B0A133BA7A828724368B12316C34B7172977DBDE2"
"065C318F4E0960155F7603E820FAD15D14288BBAFB75D48645F30F4D6E03EDFD"
"DC9266D11689239F6BBB27E57B37381B0145FEBA9B08CD62FCF5B07466D25A60";

// ---------- UTF8 -> 宽字符 ----------
static CStringW Utf8ToW(const std::string& s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    CStringW w;
    if (n > 0) {
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(),
                            w.GetBuffer(n), n);
        w.ReleaseBuffer(n);
    }
    return w;
}

// ---------- 文本置入剪贴板 ----------
static bool CopyTextToClipboard(HWND hOwner, const CStringW& text)
{
    if (!OpenClipboard(hOwner)) return false;
    EmptyClipboard();
    SIZE_T bytes = (SIZE_T)(text.GetLength() + 1) * sizeof(wchar_t);
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    bool ok = false;
    if (hMem) {
        LPVOID p = GlobalLock(hMem);
        if (p) {
            memcpy(p, text.GetString(), bytes);
            GlobalUnlock(hMem);
            if (SetClipboardData(CF_UNICODETEXT, hMem)) ok = true;
        }
        if (!ok) GlobalFree(hMem);
    }
    CloseClipboard();
    return ok;
}

// ---------- 主对话框 ----------
class CKeyDlg : public CDialog
{
public:
    CKeyDlg(CWnd* pParent = nullptr) : CDialog(IDD_MAIN, pParent) {}

protected:
    HBRUSH  m_hbrWhite = nullptr;
    CStringW m_reg211;  // 2.1.1/8.1.1 通用注册码
    CStringW m_reg200;  // 2.0.0 注册码

    virtual BOOL OnInitDialog() override
    {
        CDialog::OnInitDialog();
        m_hbrWhite = CreateSolidBrush(RGB(255, 255, 255));
        SetDlgItemText(IDC_LOG, L"请粘贴机器特征码（sq 开头的整串），然后点击【一键算号】。");
        GetDlgItem(IDC_GO)->SetFocus();
        return FALSE; // 焦点已手动设置
    }

    afx_msg void OnGo()
    {
        CEdit* pLog = (CEdit*)GetDlgItem(IDC_LOG);
        pLog->SetWindowTextW(L"");
        m_reg211.Empty();
        m_reg200.Empty();
        SetDlgItemText(IDC_REG211, L"");
        SetDlgItemText(IDC_REG200, L"");

        CStringW mc;
        GetDlgItemText(IDC_MC, mc);
        if (mc.IsEmpty()) {
            pLog->SetSel(-1, -1);
            pLog->ReplaceSel(L"未输入机器特征码！请先粘贴机器特征码。\r\n");
            return;
        }

        auto logLine = [&pLog](const CStringW& s) {
            pLog->SetSel(-1, -1);
            pLog->ReplaceSel(s + L"\r\n");
        };

        keygen::MachineCodeInfo info;
        std::string err;
        if (!keygen::ParseMachineCode(std::wstring(mc), info, err)) {
            logLine(L"[X] 解析失败：" + Utf8ToW(err));
            return;
        }
        logLine(L"[1/5] 已解析机器特征码：密文 0x78 字节，密钥 " + Utf8ToW(info.keyHex));
        logLine(L"[2/5] 3DES-ECB-PKCS7 解密成功，版本串：\"" +
                Utf8ToW(info.versionStr) + L"\"");
        logLine(L"[3/5] 硬件特征码：" + Utf8ToW(info.hwHex));

        bool regZero = (info.regHex == "000000000000000000000000");
        logLine(L"[4/5] 注册表特征码：" + Utf8ToW(info.regHex) +
                (regZero ? L"（全零，满足算号模板条件）"
                         : L"（非全零：可注册，但二次密钥可能失效，无法连接盒子）"));

        std::string r211, r200;
        bool ok211 = keygen::GenerateRegCode(info, keygen::VER_211, r211, err);
        std::string err2;
        bool ok200 = keygen::GenerateRegCode(info, keygen::VER_200, r200, err2);
        if (!ok211 || !ok200) {
            logLine(L"[X] 生成失败：" + Utf8ToW(ok211 ? err2 : err));
            return;
        }
        m_reg211 = Utf8ToW(r211);
        m_reg200 = Utf8ToW(r200);
        SetDlgItemText(IDC_REG211, m_reg211);
        SetDlgItemText(IDC_REG200, m_reg200);
        logLine(L"[5/5] 已同时生成 2.1.1/8.1.1 通用版（" +
                CStringW(std::to_wstring(r211.size()).c_str()) +
                L" 字符）与通杀 2.0.0、1.1.0 等其他版本（" +
                CStringW(std::to_wstring(r200.size()).c_str()) +
                L" 字符）注册码。");

        // 通用版自动置入剪贴板
        bool copied = CopyTextToClipboard(GetSafeHwnd(), m_reg211);
        if (copied)
            logLine(L"算号完毕！请复制注册码使用，同时注册码已自动置入剪贴板");
        else
            logLine(L"算号完毕！注册码已生成，但置入剪贴板失败，请点击复制按钮手动复制。");
    }

    afx_msg void OnCopy211()
    {
        if (!m_reg211.IsEmpty() && CopyTextToClipboard(GetSafeHwnd(), m_reg211)) {
            CEdit* pLog = (CEdit*)GetDlgItem(IDC_LOG);
            pLog->SetSel(-1, -1);
            pLog->ReplaceSel(L"已复制 2.1.1/8.1.1 通用注册码到剪贴板。\r\n");
        }
    }

    afx_msg void OnCopy200()
    {
        if (!m_reg200.IsEmpty() && CopyTextToClipboard(GetSafeHwnd(), m_reg200)) {
            CEdit* pLog = (CEdit*)GetDlgItem(IDC_LOG);
            pLog->SetSel(-1, -1);
            pLog->ReplaceSel(L"已复制通杀 2.0.0、1.1.0 等其他版本注册码到剪贴板。\r\n");
        }
    }

    afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
    {
        if (nCtlColor == CTLCOLOR_EDIT && pWnd->GetDlgCtrlID() == IDC_LOG) {
            pDC->SetTextColor(RGB(200, 0, 0));    // 红字日志
            pDC->SetBkColor(RGB(255, 255, 255));
            return m_hbrWhite;
        }
        return CDialog::OnCtlColor(pDC, pWnd, nCtlColor);
    }

    virtual void OnOK() override {} // 屏蔽回车误触

    DECLARE_MESSAGE_MAP()
};

BEGIN_MESSAGE_MAP(CKeyDlg, CDialog)
    ON_BN_CLICKED(IDC_GO, &CKeyDlg::OnGo)
    ON_BN_CLICKED(IDC_COPY211, &CKeyDlg::OnCopy211)
    ON_BN_CLICKED(IDC_COPY200, &CKeyDlg::OnCopy200)
    ON_WM_CTLCOLOR()
END_MESSAGE_MAP()

// ---------- 应用 ----------
class CKeyApp : public CWinApp
{
public:
    virtual BOOL InitInstance() override;
};

// --selftest：使用验收样例自校验，结果写入 exe 旁边 selftest_result.txt，
// 并直接以 0/1 作为进程退出码。
static void SelfTest()
{
    bool pass = false;
    std::string err, reg;
    keygen::MachineCodeInfo info;
    if (keygen::ParseMachineCode(MC_REF, info, err) &&
        keygen::GenerateRegCode(info, keygen::VER_211, reg, err)) {
        pass = (reg == REG_REF);
        if (!pass) err = "注册码与期望值不一致";
    }
    else if (err.empty()) {
        err = "未知错误";
    }

    wchar_t path[MAX_PATH] = { 0 };
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring outPath(path);
    size_t pos = outPath.find_last_of(L"\\/");
    outPath = outPath.substr(0, pos + 1) + L"selftest_result.txt";

    CStringW line;
    line.Format(L"%s\r\n%s\r\n", pass ? L"PASS" : L"FAIL",
                pass ? L"验收样例逐字节一致" : Utf8ToW(err).GetString());
    HANDLE h = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        int cb = WideCharToMultiByte(CP_UTF8, 0, line.GetString(), line.GetLength(),
                                     nullptr, 0, nullptr, nullptr);
        std::string buf(cb, '\0');
        WideCharToMultiByte(CP_UTF8, 0, line.GetString(), line.GetLength(),
                            buf.data(), cb, nullptr, nullptr);
        WriteFile(h, buf.data(), (DWORD)buf.size(), &written, nullptr);
        CloseHandle(h);
    }
    ExitProcess(pass ? 0 : 1);
}

BOOL CKeyApp::InitInstance()
{
    CWinApp::InitInstance();
    SetRegistryKey(nullptr);

    CStringW cmdLine(GetCommandLineW());
    if (cmdLine.Find(L"--selftest") >= 0) {
        SelfTest(); // 内部直接 ExitProcess 结束进程
    }

    CKeyDlg dlg;
    m_pMainWnd = &dlg;
    dlg.DoModal();
    return FALSE;
}

CKeyApp theApp;
