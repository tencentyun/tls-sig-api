#if defined(WIN32) || defined(WIN64)
#pragma warning(disable: 4819)			// file codec warning, that's boring!
#pragma warning(disable: 4099)
#endif

// ���ļ���ʾ���ļ������ӿڵ�ʹ�÷���
// ����������ǩ���ӿڵķ�����Ȼ���У��ǩ���ӿڵķ���

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

	cout << "\tgen2 sig: " << prog << " gen2 key sig_file sdkappid identifier" << endl;
	cout << "\tgen2 sig: " << prog << " gen2 5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e sig 1400001052 xiaojun" << endl;
	cout << "\tverify2 sig: " << prog << " verify2 key sig_file sdkappid identifier" << endl;
	cout << "\tverify2 sig e.g.: " << prog << " verify2 5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e sig 1400001052 xiaojun" << endl;

	cout << "\tverify sig: " << prog << " verify pub_key_file sig_file sdkappid identifier" << endl;
	cout << "\tverify sig e.g.: " << prog << " verify public.pem sig 1400001052 xiaojun" << endl;
	cout << "\tgen sig: " << prog << " genuser pri_key_file sig_file sdkappid identifier expire userbuf" << endl;
	cout << "\tgen sig e.g.: " << prog << " genuser ec_key.pem sig 1400001052 xiaojun 1024 abc" << endl;
	cout << "\tverify sig: " << prog << " verifyuser pub_key_file sig_file sdkappid identifier" << endl;
	cout << "\tverify sig e.g.: " << prog << " verifyuser public.pem sig 1400001052 xiaojun" << endl;
	cout << "\tdump sig e.g.: " << prog << " dump sigtext" << endl;
}

// Ĭ�� 180 ��Ч��
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

	// ��ȡ˽Կ�ļ�����
	char pri_key_buf[1024] = {0};
	int read_cnt = (int)fread(pri_key_buf, sizeof(char), sizeof(pri_key_buf), pri_key_fp);
	if (sizeof(pri_key_buf) > (unsigned int)read_cnt && 0 != ferror(pri_key_fp))
	{
		cout << "read file " << pri_key_file << " failed" << endl;
		return -2;
	}
	fclose(pri_key_fp);
	pri_key_fp = NULL;

	// ͨ��˽Կ�ļ����ݼ��ܴ���������� sig
	string sig;
	string err_msg;
    string str_pri_key(pri_key_buf, read_cnt);
    int ret;
    ret = gen_sig(sdkappid, identifier, str_pri_key, sig);
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

	// ��ǩ��д���ļ�
	int written_cnt = (int)fwrite(sig.c_str(), sizeof(char), sig.size(), sig_fp);
	if (sig.size() > (unsigned int)written_cnt && 0 != ferror(sig_fp))
	{
		cout << "write sig content failed" << endl;
		return -5;
	}

	cout << "generate sig ok" << endl;

	return 0;
}

// ָ����Ч������ǩ��
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

	// ��ȡ˽Կ�ļ�����
	char pri_key_buf[1024] = {0};
	int read_cnt = (int)fread(pri_key_buf, sizeof(char), sizeof(pri_key_buf), pri_key_fp);
	if (sizeof(pri_key_buf) > (unsigned int)read_cnt && 0 != ferror(pri_key_fp))
	{
		cout << "read file " << pri_key_file << " failed" << endl;
		return -2;
	}
	fclose(pri_key_fp);
	pri_key_fp = NULL;

	// ͨ��˽Կ�ļ����ݼ��ܴ���������� sig
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

	// ��ǩ��д���ļ�
	int written_cnt = (int)fwrite(sig.c_str(), sizeof(char), sig.size(), sig_fp);
	if (sig.size() > (unsigned int)written_cnt && 0 != ferror(sig_fp))
	{
		cout << "write sig content failed" << endl;
		return -5;
	}

	cout << "generate sig ok" << endl;

	return 0;
}

static int gen2_sig(const string& key, const string& sig_file,
		uint32_t sdkappid, const string& identifier)
{
	string sig;
	string err_msg;
	int ret = gen_sig_v2(sdkappid, identifier, key, 180*86400, sig, err_msg);
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

	// ��ǩ��д���ļ�
	int written_cnt = (int)fwrite(sig.c_str(), sizeof(char), sig.size(), sig_fp);
	if (sig.size() > (unsigned int)written_cnt && 0 != ferror(sig_fp))
	{
		std::cout << "write sig content failed" << std::endl;
		return -5;
	}

	std::cout << sig << std::endl;
	std::cout << "generate sig ok" << std::endl;

	return 0;
}

// У��ǩ��
static int verify_sig(string& pub_key_file, string& sig_file,
		string& sdkappid, string& identifier, bool with_userbuf = false)
{
	// ���ȶ�ȡ sig �ļ��е�����
	// ���ǵĳ�����Ȼ���õ������ַ�ʽ�����ǿ�������ʹ�õ�ʱ��϶����û�����ֱ�ӵ��ýӿ�
	// ����������ô��ֻ��Ϊ������ʹ���ϵķ��㣬���ǿ��԰� sig ������д���ļ���Ȼ������ȷ��
	// ����ȥ������������Ĳ�ȷ����
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

	// ������Կ������
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
	// ���ýӿڶ� sig ������֤
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

static int verify2_sig(const string& key, string& sig_file,
        string& sdkappid, string& identifier) {
    // ���ȶ�ȡ sig �ļ��е�����
    // ���ǵĳ�����Ȼ���õ������ַ�ʽ�����ǿ�������ʹ�õ�ʱ��϶����û�����ֱ�ӵ��ýӿ�
    // ����������ô��ֻ��Ϊ������ʹ���ϵķ��㣬���ǿ��԰� sig ������д���ļ���Ȼ������ȷ��
    // ����ȥ������������Ĳ�ȷ����
    char sig_buf[1024];
#if defined(WIN32) || defined(WIN64)
    FILE * sig_fp = NULL;
    fopen_s(&sig_fp, sig_file.c_str(), "r");
#else
    FILE* sig_fp = fopen(sig_file.c_str(), "r");
#endif
    if (!sig_fp) {
        cout << "open file " << sig_file << " failed" << endl;
        return -1;
    }

    int read_cnt = (int) fread(sig_buf, sizeof (char), sizeof (sig_buf), sig_fp);
    if (sizeof (sig_buf) > (unsigned int) read_cnt && 0 != ferror(sig_fp)) {
        cout << "read file " << sig_file << " failed" << endl;
        return -2;
    }
    fclose(sig_fp);
    sig_fp = NULL;
    string sig_str(sig_buf, read_cnt);

    SigInfo sig_info;

    sig_info.strAppid = sdkappid;
    sig_info.strIdentify = identifier;
    string err_msg;
    stringstream ss;
    ss.str(sdkappid);
    uint32_t int_sdkappid;
    ss >> int_sdkappid;
    uint32_t expire_time;
    uint32_t init_time;
    int ret = tls_check_signature_ex2(sig_str, key, int_sdkappid,
            identifier, expire_time, init_time, err_msg);
    if (0 != ret) {
        cout << "check sig faild: " << ret << ":" << err_msg << endl;
        return -5;
    }
    cout << "verify sig ok" << endl;
    cout << "expire " << expire_time << " init time " << init_time << endl;
    return 0;
}

int main(int argc, char * argv[]) {

    if (argc < 2) {
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

    int ret = 0;
    if (0 == strcmp(cmd, "gen_without_expire") && argc == 6) {
        pri_key_file = argv[2];
        sig_file = argv[3];
        sdkappid = atoi(argv[4]);
        identifier = argv[5];
        ret = gen_sig_without_expire(pri_key_file, sig_file, sdkappid, identifier);
    } else if (0 == strcmp(cmd, "gen") && argc == 6) {
        pri_key_file = argv[2];
        sig_file = argv[3];
        sdkappid = atoi(argv[4]);
        identifier = argv[5];
        ret = gen_sig(pri_key_file, sig_file, sdkappid, identifier);
    } else if (0 == strcmp(cmd, "genexpire") && argc == 7) {
        pri_key_file = argv[2];
        sig_file = argv[3];
        sdkappid = atoi(argv[4]);
        identifier = argv[5];
        expire = atoi(argv[6]);
        ret = gen_sig(pri_key_file, sig_file, sdkappid, identifier, &expire);
    } else if (0 == strcmp(cmd, "genuser") && argc == 8) {
        pri_key_file = argv[2];
        sig_file = argv[3];
        sdkappid = atoi(argv[4]);
        identifier = argv[5];
        expire = atoi(argv[6]);
        userbuf = argv[7];
        ret = gen_sig(pri_key_file, sig_file, sdkappid, identifier, &expire, &userbuf);
    } else if (0 == strcmp(cmd, "verify") && argc == 6) {
        pub_key_file = argv[2];
        sig_file = argv[3];
        sdkappid_str = argv[4];
        identifier = argv[5];
        ret = verify_sig(pub_key_file, sig_file, sdkappid_str, identifier);
    } else if (0 == strcmp(cmd, "verifyuser") && argc == 6) {
        pub_key_file = argv[2];
        sig_file = argv[3];
        sdkappid_str = argv[4];
        identifier = argv[5];
        ret = verify_sig(pub_key_file, sig_file, sdkappid_str, identifier, true);
    } else if (0 == strcmp(cmd, "dump") && argc == 3) {
        std::string json, errmsg;
        ret = tls_signature_inner::SigToJson(argv[2], json, errmsg);
        if (ret == 0) {
            cout << json << endl;
        } else {
            cout << "cmd " << cmd << " return " << ret << " " << errmsg << endl;
        }
        return 0;
    } else if (0 == strcmp(cmd, "gen2") && 6 == argc) {
        std::string key = argv[2];
        std::string sig_file = argv[3];
        std::string sdkappid_str = argv[4];
        std::string identifier = argv[5];
        ret = gen2_sig(key, sig_file, strtol(sdkappid_str.c_str(), NULL, 10), identifier);
    } else if (0 == strcmp(cmd, "verify2") && 6 == argc) {
        std::string key = argv[2];
        std::string sig_file = argv[3];
        std::string sdkappid_str = argv[4];
        std::string identifier = argv[5];
        ret = verify2_sig(key, sig_file, sdkappid_str, identifier);
    } else {
        usage(argv[0]);
        return -1;
    }

    if (0 != ret) {
        cout << "cmd " << cmd << " return " << ret << endl;
    }

    return 0;
}
