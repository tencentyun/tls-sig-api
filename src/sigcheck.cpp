#include "sigcheck.h"
#if defined(WIN32) || defined(WIN64)
#pragma warning(disable: 4267)
#endif

#include <cstring>

#include <iostream>
#include <sstream>

#include "tls_signature.h"

using namespace std;

int tls_gen_sig(
	unsigned int expire,
	const char * appid3rd,
	unsigned int sdkappid,
	const char * identifier,
	unsigned int acctype,
	char * sig,
	unsigned int sig_buff_len,
	const char * pri_key,
	unsigned int pri_key_len,
	char * err_msg,
	unsigned int err_msg_buff_len
	)
{
	string str_sig;
	string str_err_msg;
	int ret;

	ret = tls_gen_signature_ex(expire, appid3rd, sdkappid, string(identifier), acctype, str_sig, (char *)pri_key, pri_key_len, str_err_msg);
	if (0 != ret)
	{
		int err_msg_len = (static_cast<unsigned int>(str_err_msg.length())+1) > err_msg_buff_len ? (err_msg_buff_len-1) : str_err_msg.length();
		memcpy(err_msg, str_err_msg.c_str(), err_msg_len);
		err_msg[err_msg_len] = 0;
		return ret;
	}

#define OUT_OF_RANGE_MSG "sig length out of range"

	if (str_sig.length()+1 > sig_buff_len)
	{
		if (sig_buff_len >= sizeof(OUT_OF_RANGE_MSG))
		{
			memcpy(err_msg, OUT_OF_RANGE_MSG, sizeof(OUT_OF_RANGE_MSG));
		}
		return -1;
	}

	memcpy(sig, str_sig.c_str(), str_sig.length());
	sig[str_sig.length()] = 0;
	return 0;
}

int tls_vri_sig(
	const char * sig,
	const char * pub_key,
	unsigned int pub_key_len,
	unsigned int acctype,
	const char * appid3rd,
	unsigned int sdkappid,
	const char * identifier,
	char * err_msg,
	unsigned int err_msg_buff_len
	)
{
	SigInfo sig_info;
	std::string str_err_msg;

	std::stringstream ss;
	ss << acctype;
	sig_info.strAccountType = ss.str();
	ss.str("");								// clear the content
	ss << sdkappid;
	sig_info.strAppid = ss.str();
	sig_info.strAppid3Rd = appid3rd;
	sig_info.strIdentify = identifier;

	uint32_t expire_time;
	uint32_t init_time;
	int ret = tls_check_signature_ex(sig, (char *)pub_key, pub_key_len, sig_info, expire_time, init_time, str_err_msg);
	if (0 != ret)
	{
		int err_msg_len = (static_cast<unsigned int>(str_err_msg.length())+1)>err_msg_buff_len ? (err_msg_buff_len-1) : str_err_msg.length();
		memcpy(err_msg, str_err_msg.c_str(), err_msg_len);
		err_msg[err_msg_len] = 0;
		return ret;
	}

	return 0;
}

int tls_gen_sig_ex_with_expire(
	unsigned int sdkappid,
	const char * identifier,
    unsigned int expire,
	char * sig,
	unsigned int sig_buff_len,
	const char * pri_key,
	unsigned int pri_key_len,
	char * err_msg,
	unsigned int err_msg_buff_len)
{
	string str_sig;
	string str_err_msg;
	int ret;

    string str_identifier(identifier);
    string str_pri_key(pri_key, pri_key_len);
	ret = tls_gen_signature_ex2_with_expire(sdkappid, str_identifier, expire, str_sig, str_pri_key, str_err_msg);
	if (0 != ret)
	{
		int err_msg_len = (static_cast<unsigned int>(str_err_msg.length())+1) > err_msg_buff_len ? (err_msg_buff_len-1) : str_err_msg.length();
		memcpy(err_msg, str_err_msg.c_str(), err_msg_len);
		err_msg[err_msg_len] = 0;
		return ret;
	}

#define OUT_OF_RANGE_MSG "sig length out of range"

	if (str_sig.length()+1 > sig_buff_len)
	{
		if (sig_buff_len >= sizeof(OUT_OF_RANGE_MSG))
		{
			memcpy(err_msg, OUT_OF_RANGE_MSG, sizeof(OUT_OF_RANGE_MSG));
		}
		return -1;
	}

	memcpy(sig, str_sig.c_str(), str_sig.length());
	sig[str_sig.length()] = 0;
	return 0;    
}

int tls_gen_sig_ex(
	unsigned int sdkappid,
	const char * identifier,
	char * sig,
	unsigned int sig_buff_len,
	const char * pri_key,
	unsigned int pri_key_len,
	char * err_msg,
	unsigned int err_msg_buff_len)
{
	string str_sig;
	string str_err_msg;
	int ret;

    string str_identifier(identifier);
    string str_pri_key(pri_key, pri_key_len);
	ret = tls_gen_signature_ex2(sdkappid, str_identifier, str_sig, str_pri_key, str_err_msg);
	if (0 != ret)
	{
		int err_msg_len = (static_cast<unsigned int>(str_err_msg.length())+1) > err_msg_buff_len ? (err_msg_buff_len-1) : str_err_msg.length();
		memcpy(err_msg, str_err_msg.c_str(), err_msg_len);
		err_msg[err_msg_len] = 0;
		return ret;
	}

#define OUT_OF_RANGE_MSG "sig length out of range"

	if (str_sig.length()+1 > sig_buff_len)
	{
		if (sig_buff_len >= sizeof(OUT_OF_RANGE_MSG))
		{
			memcpy(err_msg, OUT_OF_RANGE_MSG, sizeof(OUT_OF_RANGE_MSG));
		}
		return -1;
	}

	memcpy(sig, str_sig.c_str(), str_sig.length());
	sig[str_sig.length()] = 0;
	return 0;    
}

int tls_vri_sig_ex(
	const char * sig,
	const char * pub_key,
	unsigned int pub_key_len,
	unsigned int sdkappid,
	const char * identifier,
    unsigned int& expire_time,
    unsigned int& init_time,
	char * err_msg,
	unsigned int err_msg_buff_len)
{
	std::string str_err_msg;

    string str_pub_key(pub_key, pub_key_len);
    string str_identifier(identifier);
	int ret = tls_check_signature_ex2(sig, str_pub_key, sdkappid, str_identifier, expire_time, init_time, str_err_msg);
	if (0 != ret)
	{
		int err_msg_len = (static_cast<unsigned int>(str_err_msg.length())+1)>err_msg_buff_len ? (err_msg_buff_len-1) : str_err_msg.length();
		memcpy(err_msg, str_err_msg.c_str(), err_msg_len);
		err_msg[err_msg_len] = 0;
		return ret;
	}

	return 0;
}
