// test_main.cpp - 算法验证测试（使用文档样例）
#include "../KeyGen.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static const wchar_t* MC_REF = // 正确示例（交付验收用例，工具版本 2.1.1）
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

static const wchar_t* MC_S1 = // 样例1 (2.1.1)
L"sq1278000149160000F16D00003F57106400000000"
L"149DABA898B61DE5F0D5F20265CEFC87FCD2A029E02A202005716DA3F0D00DE271511FD7DF0BBF68"
L"A5726DAE3C3AACE1E921D6F299937A5DFFFBEF5CF2B1F2BC24BE11479474C00782549C45DDC8DFD4"
L"A5726DAE3C3AACE1A5726DAE3C3AACE1A5726DAE3C3AACE1A5726DAE3C3AACE1EEC73A4E90C0E12A";

static const wchar_t* MC_S2 = // 样例2 (2.1.1)
L"sq1278000129000000234800005460466200000000"
L"996981964BA8B08BE8D6FF485A3ED8D333AAF591D4ABED8293FA0668AF958E3D74F80FF1ED8FC37D"
L"B4C897293D0A116499BA6CF8DAB03D984942616927680814B4C897293D0A1164B4C897293D0A1164"
L"B4C897293D0A1164B4C897293D0A1164B4C897293D0A1164B4C897293D0A1164795819AE0B791A0B";

static const wchar_t* MC_S3 = // 样例3 (2.1.1)
L"sq1278000152690000905F00005B89106400000000"
L"640BA15C83DE297F0273EF2410C26CFCB2F5E683578EAE8A13B90F269806C9354BE270BF44133AD5"
L"E25C0E0164B9AF53FF227A03BEF9A3863761478DE44B6FB3E25C0E0164B9AF53E25C0E0164B9AF53"
L"E25C0E0164B9AF53E25C0E0164B9AF53E25C0E0164B9AF53E25C0E0164B9AF53FEAC7070034EEC9E";

static const wchar_t* MC_S4 = // 样例4 (2.0.0)
L"sq1478000129000000234800002D60AD5E00000000"
L"17EC97EC3BB3CB78A5C94EE7B9051D566BB9DB8D3660ECA3C83A1675DF925BA4D7D1A55DC5D03038"
L"DBD6E479F431737FF789B9EBE6CB1F91D73108614C20EBBE5239F52407F994B70E27D2147B936343"
L"196A87F3B347C2AC196A87F3B347C2AC196A87F3B347C2AC196A87F3B347C2AC71CE92134C656C0F";

static void DumpInfo(const char* tag, const keygen::MachineCodeInfo& mc)
{
    printf("[%s] 密文长度=%d\n", tag, mc.cipherLen);
    printf("[%s] 机器码密钥=%s\n", tag, mc.keyHex.c_str());
    printf("[%s] 版本字符串=\"%s\"\n", tag, mc.versionStr.c_str());
    printf("[%s] 硬件特征码=%s\n", tag, mc.hwHex.c_str());
    printf("[%s] 注册表特征码=%s\n", tag, mc.regHex.c_str());
}

int main()
{
    bool allOk = true;
    keygen::MachineCodeInfo mc;
    std::string reg, err;

    // ---- 用例1：参考样例（验收用例，必须逐字节一致，工具版本 2.1.1） ----
    printf("== 用例1: 参考样例(验收用例, 2.1.1) ==\n");
    if (!keygen::ParseMachineCode(MC_REF, mc, err)) {
        printf("  解析失败: %s\n  => FAIL\n", err.c_str());
        return 1;
    }
    DumpInfo("REF", mc);
    reg.clear(); err.clear();
    bool ok = keygen::GenerateRegCode(mc, keygen::VER_211, reg, err);
    if (!ok) printf("  生成错误: %s\n", err.c_str());
    if (ok) ok = (reg == REG_REF);
    printf("  生成=%s\n  期望=%s\n  长度 生成=%zu 期望=%zu\n  => %s\n\n",
           reg.c_str(), REG_REF, reg.size(), strlen(REG_REF), ok ? "PASS (逐字节一致)" : "FAIL");
    if (!ok) allOk = false;

    // ---- 用例2：样例4 (2.0.0，结构校验；其二次密钥密文依赖未知密钥派生，无法逐字节复现) ----
    printf("== 用例2: 样例4 (2.0.0, 结构校验) ==\n");
    if (!keygen::ParseMachineCode(MC_S4, mc, err)) {
        printf("  解析失败: %s\n  => FAIL\n", err.c_str());
        return 1;
    }
    DumpInfo("S4", mc);
    ok = keygen::GenerateRegCode(mc, keygen::VER_200, reg, err);
    bool headOk = ok && reg.rfind("700001BE18000084670000F9E4ED5C00000000", 0) == 0;
    bool lenOk  = ok && reg.size() == 262; // 19字节头 + 112字节密文
    printf("  注册码=%s\n  => 头部:%s 长度:%s\n\n", reg.c_str(),
           headOk ? "OK" : "FAIL", lenOk ? "OK" : "FAIL");
    if (!ok || !headOk || !lenOk) allOk = false;

    // ---- 用例3：样例1/2/3 (2.1.1，结构校验) ----
    const wchar_t* codes[] = { MC_S1, MC_S2, MC_S3 };
    for (int i = 0; i < 3; ++i) {
        printf("== 用例%d: 样例%d (2.1.1, 结构校验) ==\n", i + 3, i + 1);
        if (!keygen::ParseMachineCode(codes[i], mc, err)) {
            printf("  解析失败: %s\n  => FAIL\n\n", err.c_str());
            allOk = false;
            continue;
        }
        DumpInfo("S", mc);
        ok = keygen::GenerateRegCode(mc, keygen::VER_211, reg, err);
        bool hOk = ok && reg.rfind("800001D62C0000AE7200003333333333333333", 0) == 0;
        bool lOk = ok && reg.size() == 294; // 19字节头 + 128字节密文
        printf("  前32字符=%s...\n  => 头部:%s 长度:%s\n\n",
               reg.substr(0, 32).c_str(), hOk ? "OK" : "FAIL", lOk ? "OK" : "FAIL");
        if (!ok || !hOk || !lOk) allOk = false;
    }

    printf(allOk ? "*** 全部测试通过 ***\n" : "*** 存在失败用例 ***\n");
    return allOk ? 0 : 1;
}
