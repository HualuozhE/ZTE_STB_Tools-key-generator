// KeyGen.h - ZTE STB Tools 注册码生成核心算法
// 原理：机器码(sq...)去前缀后为 HEX 字节流：
//   byte0    : 头(0x12/0x14)
//   byte1    : 密文长度(如 0x78)
//   byte2-3  : 0x0001
//   byte4-19 : 16 字节机器码密钥(HEX)
//   byte20-  : 3DES 密文
// 密钥使用方式：16 字节后面补 8 字节 0x00 扩充至 24 字节，3DES/ECB/PKCS7。
// 解密后：byte0-47 版本字符串，byte48-63 硬件特征码，byte64-75 注册表特征码。
#pragma once
#include <string>
#include <vector>
#include <windows.h>

namespace keygen {

enum StbVersion { VER_211 = 0x0C, VER_200 = 0x0E };

struct MachineCodeInfo {
    std::string hwHex;       // 硬件特征码 16 字节 HEX（32 字符）
    std::string regHex;      // 注册表特征码 12 字节 HEX（24 字符）
    std::string versionStr;  // 解密得到的版本字符串（去尾 0）
    std::string keyHex;      // 机器码密钥 16 字节 HEX
    int         cipherLen = 0; // 密文长度（字节）
};

// 3DES/ECB/PKCS7，key24 必须为 24 字节
bool Des3Encrypt(const BYTE* key24, const BYTE* plain, size_t plainLen,
                 std::vector<BYTE>& out, std::string& err);
bool Des3Decrypt(const BYTE* key24, const BYTE* cipher, size_t cipherLen,
                 std::vector<BYTE>& out, std::string& err);

// 3DES/ECB 无填充版本（数据长度必须是 8 的倍数）
bool Des3EncryptRaw(const BYTE* key24, const BYTE* plain, size_t plainLen,
                    std::vector<BYTE>& out, std::string& err);
bool Des3DecryptRaw(const BYTE* key24, const BYTE* cipher, size_t cipherLen,
                    std::vector<BYTE>& out, std::string& err);

// 解析机器码（宽字符输入，容忍空白、大小写、可选 sq 前缀）
bool ParseMachineCode(const std::wstring& input, MachineCodeInfo& info, std::string& err);

// 由机器码信息生成注册码（HEX 大写字符串）。ver 由界面选择（工具版本）。
bool GenerateRegCode(const MachineCodeInfo& mc, StbVersion ver,
                     std::string& regHex, std::string& err);

} // namespace keygen
