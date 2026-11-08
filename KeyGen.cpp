// KeyGen.cpp - ZTE STB Tools 注册码生成核心算法实现（BCrypt/CNG, 3DES ECB PKCS7）
#include "KeyGen.h"
#include <bcrypt.h>
#include <string>
#include <vector>
#include <cctype>

#pragma comment(lib, "bcrypt.lib")

namespace keygen {

// ---------- HEX 辅助 ----------
static int HexVal(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void ToHex(const BYTE* data, size_t len, std::string& out)
{
    static const char* digits = "0123456789ABCDEF";
    out.reserve(out.size() + len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0F]);
    }
}

// ---------- 3DES/ECB 核心（可带/不带 PKCS7 填充） ----------
namespace {

struct CngGuard {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    ~CngGuard()
    {
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    }
};

bool PrepareKey(const BYTE* key24, CngGuard& g, std::string& err)
{
    NTSTATUS st = BCryptOpenAlgorithmProvider(&g.hAlg, BCRYPT_3DES_ALGORITHM, nullptr, 0);
    if (st != 0) { err = "BCryptOpenAlgorithmProvider 失败"; return false; }
    wchar_t mode[] = L"ChainingModeECB";
    st = BCryptSetProperty(g.hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)mode,
                           (ULONG)((wcslen(mode) + 1) * sizeof(wchar_t)), 0);
    if (st != 0) { err = "设置 ECB 模式失败"; return false; }
    st = BCryptGenerateSymmetricKey(g.hAlg, &g.hKey, nullptr, 0,
                                    (PUCHAR)key24, 24, 0);
    if (st != 0) { err = "生成 3DES 密钥失败"; return false; }
    return true;
}

bool CryptCore(const BYTE* key24, const BYTE* in, size_t inLen,
               std::vector<BYTE>& out, bool encrypt, bool padding, std::string& err)
{
    if (!padding && (inLen % 8) != 0) { err = "数据长度不是 8 的倍数"; return false; }
    CngGuard g;
    if (!PrepareKey(key24, g, err)) return false;
    ULONG flags = padding ? BCRYPT_BLOCK_PADDING : 0;
    ULONG cb = 0;
    NTSTATUS st = encrypt
        ? BCryptEncrypt(g.hKey, (PUCHAR)in, (ULONG)inLen, nullptr, nullptr, 0,
                        nullptr, 0, &cb, flags)
        : BCryptDecrypt(g.hKey, (PUCHAR)in, (ULONG)inLen, nullptr, nullptr, 0,
                        nullptr, 0, &cb, flags);
    if (st != 0) { err = "CNG 取长度失败"; return false; }
    out.resize(cb ? cb : inLen);
    ULONG cbDone = 0;
    st = encrypt
        ? BCryptEncrypt(g.hKey, (PUCHAR)in, (ULONG)inLen, nullptr, nullptr, 0,
                        out.data(), (ULONG)out.size(), &cbDone, flags)
        : BCryptDecrypt(g.hKey, (PUCHAR)in, (ULONG)inLen, nullptr, nullptr, 0,
                        out.data(), (ULONG)out.size(), &cbDone, flags);
    if (st != 0) {
        err = encrypt ? "加密失败"
                      : "解密失败（密文或密钥不正确？）";
        return false;
    }
    out.resize(cbDone);
    return true;
}

} // namespace

bool Des3Encrypt(const BYTE* key24, const BYTE* plain, size_t plainLen,
                 std::vector<BYTE>& out, std::string& err)
{
    return CryptCore(key24, plain, plainLen, out, true, true, err);
}

bool Des3Decrypt(const BYTE* key24, const BYTE* cipher, size_t cipherLen,
                 std::vector<BYTE>& out, std::string& err)
{
    return CryptCore(key24, cipher, cipherLen, out, false, true, err);
}

bool Des3EncryptRaw(const BYTE* key24, const BYTE* plain, size_t plainLen,
                    std::vector<BYTE>& out, std::string& err)
{
    return CryptCore(key24, plain, plainLen, out, true, false, err);
}

bool Des3DecryptRaw(const BYTE* key24, const BYTE* cipher, size_t cipherLen,
                    std::vector<BYTE>& out, std::string& err)
{
    return CryptCore(key24, cipher, cipherLen, out, false, false, err);
}

// ---------- 机器码解析 ----------
bool ParseMachineCode(const std::wstring& input, MachineCodeInfo& info, std::string& err)
{
    info = MachineCodeInfo{};
    // 收集 HEX 字符（忽略 sq 前缀与所有空白/标点）
    std::string hex;
    hex.reserve(input.size());
    for (wchar_t wc : input) {
        if (wc < 0x80) {
            int v = HexVal((int)(char)wc);
            if (v >= 0) hex.push_back((char)wc);
        }
    }
    // 去掉开头的 sq（若用户保留了前缀，s 不是 HEX 字符自然被过滤，q 同理）
    if (hex.size() < 4 + 32 + 16) { // 头4字节 + 密钥16字节 + 至少2块密文
        err = "机器特征码 HEX 内容太短，请检查粘贴内容";
        return false;
    }

    // HEX 字符串 -> 字节流（奇数长度丢弃末位）
    size_t nBytes = hex.size() / 2;
    std::vector<BYTE> raw(nBytes);
    for (size_t i = 0; i < nBytes; ++i)
        raw[i] = (BYTE)((HexVal(hex[i * 2]) << 4) | HexVal(hex[i * 2 + 1]));

    if (nBytes < 20 + 16) { // 头4字节 + 密钥16字节 至少再带2块密文
        err = "机器特征码 HEX 内容太短，请检查粘贴内容";
        return false;
    }

    int cipherLen = raw[1];
    if (cipherLen <= 0 || (cipherLen % 8) != 0 || nBytes < (size_t)(20 + cipherLen)) {
        err = "机器特征码格式不正确（密文长度字段无效或数据不足）";
        return false;
    }

    info.cipherLen = cipherLen;
    ToHex(raw.data() + 4, 16, info.keyHex); // byte4-19

    // 组装密钥：16 字节 + 8 字节 0 扩充至 24 字节
    BYTE key24[24] = { 0 };
    memcpy(key24, raw.data() + 4, 16);

    std::vector<BYTE> plain;
    if (!Des3Decrypt(key24, raw.data() + 20, (size_t)cipherLen, plain, err))
        return false;
    if (plain.size() < 76) {
        err = "解密结果长度异常";
        return false;
    }

    ToHex(plain.data() + 48, 16, info.hwHex);   // 硬件特征码
    ToHex(plain.data() + 64, 12, info.regHex);  // 注册表特征码

    // 版本字符串：byte0-47，去除尾部 0
    size_t n = 48;
    while (n > 0 && plain[n - 1] == 0) --n;
    info.versionStr.assign((const char*)plain.data(), n);
    return true;
}

// ---------- 注册码生成 ----------
bool GenerateRegCode(const MachineCodeInfo& mc, StbVersion ver,
                     std::string& regHex, std::string& err)
{
    // 反查 HEX 字节
    auto unhex = [](const std::string& s) {
        std::vector<BYTE> v;
        v.reserve(s.size() / 2);
        for (size_t i = 0; i + 1 < s.size(); i += 2)
            v.push_back((BYTE)((HexVal(s[i]) << 4) | HexVal(s[i + 1])));
        return v;
    };

    // 各版本常量（摘自算号模板）
    static const BYTE KEY_PREFIX_211[8] = { 0xD6,0x2C,0x00,0x00,0xAE,0x72,0x00,0x00 };
    static const BYTE KEY_PREFIX_200[8] = { 0xBE,0x18,0x00,0x00,0x84,0x67,0x00,0x00 };
    static const BYTE FILLER_211[8]     = { 0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33 };
    static const BYTE FILLER_200[8]     = { 0xF9,0xE4,0xED,0x5C,0x00,0x00,0x00,0x00 };
    static const BYTE BLOB_211[] = {
        0x01,0xCD,0xFC,0xC9,0x6F,0x94,0x49,0x32,0x99,0x8E,
        0x91,0x74,0x57,0x0B,0xF2,0xF6,0x00,0x75,0x4B,0x49,
        0x68,0x4F,0x2F,0x72,0x82,0x62,0xA2,0x81,0xDD,0x96,
        0x17,0x03,0xC3,0x54,0x84,0xE5,0xDA,0xBC,0x79,0x83,
        0x3F,0x71,0x70,0x32,0xE0,0x3D,0xC1,0x33,0x0F,0xB0,
        0x9B,0xBF,0xBE,0xA7,0xE6,0x16,0x4D,0xD7,0xC4,0x22,
        0xE4,0x1C,0xE3,0x95,0x0B,0xE5,0xA9,0xD6,0xF8,0xAD,
        0x31,0xBB,0x18,0x20,0x67,0xB1,0x5F,0x6B,0x17,0x38 };
    static const BYTE BLOB_200[] = {
        0xD0,0x69,0xF5,0x8C,0x15,0xFC,0x4A,0xA4,0x80,0x7D,
        0x88,0x89,0x76,0x42,0x2A,0xD2,0x12,0x61,0x48,0x31,
        0x37,0xBE,0x9E,0x24,0xA5,0xB3,0xE9,0xB3,0xCB,0xDC,
        0x80,0x96,0xF0,0x20,0xAB,0x07,0xF2,0xBD,0x01,0xD7,
        0xB0,0xF7,0x5C,0x69,0x4E,0x82,0x98,0x06,0x2A,0x55,
        0x91,0x4F,0x29,0x78,0xFF,0x98,0x36,0x26,0x16,0x91,
        0x61,0xD1,0x56,0x6B };

    bool v211 = (ver == VER_211);
    const BYTE verByte     = v211 ? 0x0C : 0x0E;
    const BYTE* keyPrefix  = v211 ? KEY_PREFIX_211 : KEY_PREFIX_200;
    const BYTE* filler     = v211 ? FILLER_211     : FILLER_200;
    const size_t blobLen   = v211 ? sizeof(BLOB_211) : sizeof(BLOB_200);
    const BYTE* blob       = v211 ? BLOB_211 : BLOB_200;
    const BYTE  secKeyLen  = v211 ? 0x50 : 0x40;      // 二次密钥密文长度字段
    const BYTE  totalLen   = v211 ? 0x80 : 0x70;      // 注册码头部的密文长度字段

    std::vector<BYTE> hw  = unhex(mc.hwHex);
    std::vector<BYTE> reg = unhex(mc.regHex);
    if (hw.size() != 16 || reg.size() != 12) {
        err = "特征码数据异常";
        return false;
    }

    // 加密前明文：硬件特征码 + 注册表特征码 + 版本 + 有效期 + 分隔 + 二次密钥密文 + 结尾
    std::vector<BYTE> plain;
    plain.reserve(16 + 12 + 7 + blobLen + 5);
    plain.insert(plain.end(), hw.begin(), hw.end());
    plain.insert(plain.end(), reg.begin(), reg.end());
    plain.push_back(verByte);                 // 版本
    plain.push_back(0x17); plain.push_back(0x01); plain.push_back(0x01); // 起始 2023-01-01
    plain.push_back(0x7F); plain.push_back(0x01); plain.push_back(0x01); // 截止(长期)
    plain.push_back(0x00);                    // 分隔
    plain.push_back(secKeyLen);               // 二次密钥密文长度
    plain.push_back(0x00);                    // 分隔
    plain.insert(plain.end(), blob, blob + blobLen);
    plain.push_back(0x2C);                    // 结尾 5 字节
    plain.push_back(0x00);
    plain.push_back(0x01);
    plain.push_back(v211 ? 0x3E : 0x36);
    plain.push_back(v211 ? 0x7F : 0x5F);

    // 注册码密钥：8 字节前缀 + 注册表特征码后 8 字节，再补 0 至 24 字节
    BYTE key24[24] = { 0 };
    memcpy(key24, keyPrefix, 8);
    memcpy(key24 + 8, reg.data() + 4, 8);

    std::vector<BYTE> cipher;
    if (!Des3Encrypt(key24, plain.data(), plain.size(), cipher, err))
        return false;

    // 组装注册码：长度(1) + 0001(2) + 密钥前8字节 + 8字节填充 + 密文
    regHex.clear();
    BYTE head[19];
    head[0] = totalLen;
    head[1] = 0x00; head[2] = 0x01;
    memcpy(head + 3, keyPrefix, 8);
    memcpy(head + 11, filler, 8);
    ToHex(head, 19, regHex);
    ToHex(cipher.data(), cipher.size(), regHex);
    return true;
}

} // namespace keygen
