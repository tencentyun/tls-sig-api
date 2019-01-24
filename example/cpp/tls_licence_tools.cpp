#if defined(WIN32) || defined(WIN64)
#pragma warning(disable: 4819)			// file codec warning, that's boring!
#pragma warning(disable: 4099)
#endif

// 此文件演示了文件两个接口的使用方法
// 首先是生成签名接口的方法，然后的校验签名接口的方法

#include <stdlib.h>
#include <string>
#include <cstring>
#include <sstream>
#include <iostream>
#include <fstream>
#include "tls_signature.h"

using namespace std;

static void usage(const string& prog)
{
	cout << "current version: " << API_VERSION << endl;
	cout << "Usage:" << endl;
	cout << "\tgen sig: " << prog << " gen_without_expire pri_key_file sig_file sdkappid identifier" << endl;
	cout << "\tgen sig e.g.: " << prog << " gen_without_expire ec_key.pem sig 1400001052 xiaojun" << endl;
	cout << "\tgen sig: " << prog << " gen pri_key_file sig_file sdkappid identifier" << endl;
	cout << "\tgen sig e.g.: " << prog << " gen ec_key.pem sig 1400001052 xiaojun" << endl;
	cout << "\tgen sig: " << prog << " genexpire pri_key_file sig_file sdkappid identifier expiredtime" << endl;
	cout << "\tgen sig e.g.: " << prog << " genexpire ec_key.pem sig 1400001052 xiaojun 31536000" << endl;
	cout << "\tverify sig: " << prog << " verify pub_key_file sig_file sdkappid identifier" << endl;
	cout << "\tverify sig e.g.: " << prog << " verify public.pem sig 1400001052 xiaojun" << endl;
	cout << "\tgen sig: " << prog << " genuser pri_key_file sig_file sdkappid identifier expire userbuf" << endl;
	cout << "\tgen sig e.g.: " << prog << " genuser ec_key.pem sig 1400001052 xiaojun 1024 abc" << endl;
	cout << "\tverify sig: " << prog << " verifyuser pub_key_file sig_file sdkappid identifier" << endl;
	cout << "\tverify sig e.g.: " << prog << " verifyuser public.pem sig 1400001052 xiaojun" << endl;
	cout << "\tdump sig e.g.: " << prog << " dump sigtext" << endl;
}

// 默认 180 有效期
static int gen_sig_without_expire(const string& pri_key_file, const string& sig_file, uint32_t sdkappid, const string& identifier)
{
#if defined(WIN32) || defined(WIN64)
	FILE * pri_key_fp = NULL;
	fopen_s(&pri_key_fp, pri_key_file.c_str(), "r");
#else
	FILE * pri_key_fp = fopen(pri_key_file.c_str(), "r");
#endif
	if (!pri_key_fp)
	{
		cout << "open file " << pri_key_file << " failed" << endl;
		return -1;
	}

	// 读取私钥文件内容
	char pri_key_buf[1024] = {0};
	int read_cnt = (int)fread(pri_key_buf, sizeof(char), sizeof(pri_key_buf), pri_key_fp);
	if (sizeof(pri_key_buf) > (unsigned int)read_cnt && 0 != ferror(pri_key_fp))
	{
		cout << "read file " << pri_key_file << " failed" << endl;
		return -2;
	}
	fclose(pri_key_fp);
	pri_key_fp = NULL;

	// 通过私钥文件内容加密传入参数生成 sig
	string sig;
	string err_msg;
    string str_pri_key(pri_key_buf, read_cnt);
    int ret;
    ret = genSig(sdkappid, identifier, str_pri_key, sig);
    if (0 != ret) {
        cout << "error msg: " << err_msg << " return " << ret << endl;
        return -3;
    }

#if defined(WIN32) || defined(WIN64)
	FILE * sig_fp = NULL;
	fopen_s(&sig_fp, sig_file.c_str(), "w+");
#else
	FILE* sig_fp = fopen(sig_file.c_str(),"w+");
#endif
	if (!sig_fp)
	{
		cout << "open file " << sig_file << "failed" << endl;
		return -4;
	}

	// 将签名写入文件
	int written_cnt = (int)fwrite(sig.c_str(), sizeof(char), sig.size(), sig_fp);
	if (sig.size() > (unsigned int)written_cnt && 0 != ferror(sig_fp))
	{
		cout << "write sig content failed" << endl;
		return -5;
	}

	cout << "generate sig ok" << endl;

	return 0;
}

// 指定有效期生成签名
static int gen_sig(const string& pri_key_file, const string& sig_file, uint32_t sdkappid, const string& identifier, int *expire = NULL, std::string *userbuf = NULL)
{
#if defined(WIN32) || defined(WIN64)
	FILE * pri_key_fp = NULL;
	fopen_s(&pri_key_fp, pri_key_file.c_str(), "r");
#else
	FILE * pri_key_fp = fopen(pri_key_file.c_str(), "r");
#endif
	if (!pri_key_fp)
	{
		cout << "open file " << pri_key_file << " failed" << endl;
		return -1;
	}

	// 读取私钥文件内容
	char pri_key_buf[1024] = {0};
	int read_cnt = (int)fread(pri_key_buf, sizeof(char), sizeof(pri_key_buf), pri_key_fp);
	if (sizeof(pri_key_buf) > (unsigned int)read_cnt && 0 != ferror(pri_key_fp))
	{
		cout << "read file " << pri_key_file << " failed" << endl;
		return -2;
	}
	fclose(pri_key_fp);
	pri_key_fp = NULL;

	// 通过私钥文件内容加密传入参数生成 sig
	string sig;
	string err_msg;
    string str_pri_key(pri_key_buf, read_cnt);
    int ret;
    if(userbuf && expire){
        ret = tls_gen_userbuf_ticket(sdkappid, identifier, *expire, str_pri_key, *userbuf, sig, err_msg);
    }
    else {
        if (expire)
            ret = tls_gen_signature_ex2_with_expire(
                sdkappid, identifier, *expire, sig, str_pri_key, err_msg);
        else
            ret = tls_gen_signature_ex2(sdkappid, identifier, sig, str_pri_key,
                                        err_msg);
        if (0 != ret) {
            cout << "error msg: " << err_msg << " return " << ret << endl;
            return -3;
        }
	}

#if defined(WIN32) || defined(WIN64)
	FILE * sig_fp = NULL;
	fopen_s(&sig_fp, sig_file.c_str(), "w+");
#else
	FILE* sig_fp = fopen(sig_file.c_str(),"w+");
#endif
	if (!sig_fp)
	{
		cout << "open file " << sig_file << "failed" << endl;
		return -4;
	}

	// 将签名写入文件
	int written_cnt = (int)fwrite(sig.c_str(), sizeof(char), sig.size(), sig_fp);
	if (sig.size() > (unsigned int)written_cnt && 0 != ferror(sig_fp))
	{
		cout << "write sig content failed" << endl;
		return -5;
	}

	cout << "generate sig ok" << endl;

	return 0;
}

// 校验签名
static int verify_sig(string& pub_key_file, string& sig_file, string& sdkappid, string& identifier, bool with_userbuf = false)
{
	// 首先读取 sig 文件中的内容
	// 我们的程序虽然是用的是这种方式，但是开发者在使用的时候肯定是用缓冲区直接调用接口
	// 这里这里这么做只是为了我们使用上的方便，我们可以把 sig 的内容写入文件，然后检查正确性
	// 而免去命令行上输入的不确定性
	char sig_buf[1024];
#if defined(WIN32) || defined(WIN64)
	FILE * sig_fp = NULL;
	fopen_s(&sig_fp, sig_file.c_str(), "r");
#else
	FILE* sig_fp = fopen(sig_file.c_str(), "r");
#endif
	if (!sig_fp)
	{
		cout << "open file " << sig_file << " failed" << endl;
		return -1;
	}

	int read_cnt = (int)fread(sig_buf, sizeof(char), sizeof(sig_buf), sig_fp);
	if (sizeof(sig_buf) > (unsigned int)read_cnt && 0 != ferror(sig_fp))
	{
		cout << "read file " << sig_file << " failed" << endl;
		return -2;
	}
	fclose(sig_fp);
	sig_fp = NULL;
	string sig_str(sig_buf, read_cnt); 

	// 读出公钥的内容
#if defined(WIN32) || defined(WIN64)
	FILE * pub_key_fp = NULL;
	fopen_s(&pub_key_fp, pub_key_file.c_str(), "r");
#else
	FILE * pub_key_fp = fopen(pub_key_file.c_str(), "r");
#endif
	if (!pub_key_fp)
	{
		cout << "open file " << pub_key_file << " faild" << endl;
		return -3;
	}

	char pub_key_buf[1024] = { 0 };
	read_cnt = (int)fread(pub_key_buf, sizeof(char), sizeof(pub_key_buf), pub_key_fp);
	if (sizeof(pub_key_buf) > (unsigned int)read_cnt && 0 != ferror(pub_key_fp))
	{
		cout << "read file " << pub_key_file << " failed" << endl;
		return -4;
	}
	fclose(pub_key_fp);
	pub_key_fp = NULL;

	SigInfo sig_info;

	sig_info.strAppid = sdkappid;
	sig_info.strIdentify = identifier;
	string err_msg;
	// 调用接口对 sig 进行验证
    string str_pub_key(pub_key_buf, read_cnt);
    stringstream ss;
    ss.str(sdkappid);
    uint32_t int_sdkappid;
    ss >> int_sdkappid;
    uint32_t expire_time;
    uint32_t init_time;
    std::string userbuf;
    int ret = with_userbuf
                  ? tls_check_userbuf_ticket(sig_str, str_pub_key, int_sdkappid,
                                             identifier, expire_time, init_time,
                                             userbuf, err_msg)
                  : tls_check_signature_ex2(sig_str, str_pub_key, int_sdkappid,
                                            identifier, expire_time, init_time,
                                            err_msg);
    if (0 != ret)
	{
		cout << "check sig faild: " << ret << ":" << err_msg << endl;
		return -5;
	}

	cout << "verify sig ok" << endl;
	cout << "expire " << expire_time << " init time " << init_time << endl;
    if(with_userbuf)
	cout << "userbuf:" << userbuf << endl;

	return 0;
}

int main(int argc, char * argv[])
{
    if (argc < 2)
    {
        usage(argv[0]);
		return -1;
    }

	const char * cmd = argv[1];
    string pri_key_file;
    string pub_key_file;
    string sig_file;
    int sdkappid;
    string sdkappid_str;
    string identifier;
    std::string userbuf;
	int expire;
    
    int ret;
    if (0 == strcmp(cmd, "gen_without_expire") && argc == 6)
    {
        pri_key_file = argv[2];
        sig_file = argv[3];
        sdkappid = atoi(argv[4]);
        identifier = argv[5];
        ret = gen_sig_without_expire(pri_key_file, sig_file, sdkappid, identifier);
    }
    else if (0 == strcmp(cmd, "gen") && argc == 6)
    {
        pri_key_file = argv[2];
        sig_file = argv[3];
        sdkappid = atoi(argv[4]);
        identifier = argv[5];
        ret = gen_sig(pri_key_file, sig_file, sdkappid, identifier);
    }
	else if (0 == strcmp(cmd, "genexpire") && argc == 7)
	{
		pri_key_file = argv[2];
        sig_file = argv[3];
        sdkappid = atoi(argv[4]);
        identifier = argv[5];
		expire = atoi(argv[6]);
        ret = gen_sig(pri_key_file, sig_file, sdkappid, identifier, &expire);
	}
    else if (0 == strcmp(cmd, "genuser") && argc == 8) {
        pri_key_file = argv[2];
        sig_file = argv[3];
        sdkappid = atoi(argv[4]);
        identifier = argv[5];
		expire = atoi(argv[6]);
        userbuf = argv[7];
        ret = gen_sig(pri_key_file, sig_file, sdkappid, identifier, &expire, &userbuf);
    }
    else if (0 == strcmp(cmd, "verify") && argc == 6)
    {
        pub_key_file = argv[2];
        sig_file = argv[3];
        sdkappid_str = argv[4];
        identifier = argv[5];
        ret = verify_sig(pub_key_file, sig_file, sdkappid_str, identifier);
    }
    else if (0 == strcmp(cmd, "verifyuser") && argc == 6)
    {
        pub_key_file = argv[2];
        sig_file = argv[3];
        sdkappid_str = argv[4];
        identifier = argv[5];
        ret = verify_sig(pub_key_file, sig_file, sdkappid_str, identifier, true);
    }
    else if (0 == strcmp(cmd, "dump") && argc == 3){
        std::string json, errmsg;
        ret = tls_signature_inner::SigToJson(argv[2], json, errmsg);
        if(ret == 0){
            cout << json << endl;
        }
        else {
            cout << "cmd " << cmd << " return " << ret  << " " << errmsg << endl;
        }
        return 0;
    }
    else
    {
        usage(argv[0]);
		return -1;
    }
	
	if (0 != ret)
	{
		cout << "cmd " << cmd << " return " << ret << endl;
	}

    return 0;
}
