#include "tls_signature.h"
#if defined(WIN32) || defined(WIN64)
#pragma warning(disable: 4819)			// file codec warning, that's boring!
#endif

#include <cstdio>
#include <ctime>
#include <cstring>

#ifdef USE_OPENSSL
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/pem.h"
#else
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/base64.h"
#endif
#include "zlib.h"

#include <iomanip>
#include <sstream>

#define fmt tls_signature_fmt
#define FMT_NO_FMT_STRING_ALIAS
#include "fmt/printf.h"

#define rapidjson tls_signature_rapidjson
#include "rapidjson/writer.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/pointer.h"

#if defined(WIN32) || defined(WIN64)
#pragma warning(disable: 4819)
#pragma warning(disable: 4267)
#pragma warning(disable: 4244)
#define snprintf(buf, buf_cnt, fmt, ...) _snprintf_s(buf, buf_cnt,  _TRUNCATE, fmt, ##__VA_ARGS__)
#define sscanf(content, fmt, ...) sscanf_s(content, fmt, ##__VA_ARGS__)
#endif

#define JSON_STRING \
	"{ \
    \"TLS.account_type\": \"%d\",\
    \"TLS.identifier\": \"%s\",\
    \"TLS.appid_at_3rd\": \"%s\",\
    \"TLS.sdk_appid\": \"%d\",\
    \"TLS.expire_after\": \"%d\",\
    \"TLS.version\": \"%s\"\
    }"

#define DEFAULT_EXPIRE  (24*3600*180)        // 默认有效期，180 天
#define TIME_UT_FORM 1
#define BASE_TYPE "account_type,identifier,sdk_appid,time,expire_after"

using namespace std;

namespace tls_signature_inner{

//去掉某些base64中生成的\r\n space
static std::string base64_strip(const void* data, size_t data_len)
{
    const char* d = static_cast<const char*>(data);
    std::string s;
    s.reserve(data_len);
    for (size_t i = 0; i < data_len; ++i) {
        if (isspace(d[i])) continue;
        s.append(1, d[i]);
    }
    return s;
}

/**********************华丽的分割线************************************
***适应url方式,替换标准base64编码，'+' => '*', '/' => '-', '=' => '_'**
**********************************************************************/
#ifdef USE_OPENSSL
static int base64_encode(const void* data, size_t data_len, std::string &base64_buffer){
    div_t res = std::div(data_len, 3);
    size_t outlen = res.quot * 4 + (res.rem ? 4 : 0);
    base64_buffer.resize(outlen);
    EVP_EncodeBlock(reinterpret_cast<uint8_t*>(const_cast<char*>(base64_buffer.data())), reinterpret_cast<const uint8_t*>(data), data_len);
    return 0;
}
static int base64_decode(const char* data, size_t data_len, std::string &raw){
    raw.resize(data_len);
    std::string base64 = base64_strip(data, data_len);
    int outlen = EVP_DecodeBlock(
        reinterpret_cast<uint8_t*>(const_cast<char*>(raw.data())),
        reinterpret_cast<const uint8_t*>(base64.data()), base64.size());
    if(outlen < 0) return outlen;
    if (base64.size() > 1 && base64[base64.size() - 1] == '=') {
        --outlen;
        if (base64.size() > 2 && base64[base64.size() - 2] == '=') --outlen;
    }
    raw.resize(outlen);
    return 0;
}
#else
static int base64_encode(const void* data, size_t data_len, std::string &base64_buffer){
    size_t outlen = 0;
    int ret = mbedtls_base64_encode(NULL, 0, &outlen, reinterpret_cast<const uint8_t*>(data), data_len);
    if(ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)return ret;
    base64_buffer.resize(outlen);
    ret = mbedtls_base64_encode(
        reinterpret_cast<uint8_t*>(const_cast<char*>(base64_buffer.data())),
        base64_buffer.size(), &outlen, reinterpret_cast<const uint8_t*>(data), data_len);
    base64_buffer.resize(outlen);
    return ret;
}
static int base64_decode(const char* data, size_t data_len, std::string &raw){
    size_t outlen = 0;
    std::string base64 = base64_strip(data, data_len);
    int ret = mbedtls_base64_decode(
        NULL, 0, &outlen, reinterpret_cast<const uint8_t*>(base64.data()),
        base64.size());
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) return ret;
    raw.resize(outlen);
    ret = mbedtls_base64_decode(
        reinterpret_cast<uint8_t*>(const_cast<char*>(raw.data())), raw.size(),
        &outlen, reinterpret_cast<const uint8_t*>(base64.data()),
        base64.size());
    return ret;
}
#endif
static int base64_encode_url(const void *data, size_t data_len, std::string &base64){
    int ret = base64_encode(data, data_len, base64);
    if(ret != 0)return ret;
    for(size_t i=0;i<base64.size();++i){
        switch(base64[i]){
        case '+':
            base64[i] = '*';
            break;
        case '/':
            base64[i] = '-';
            break;
        case '=':
            base64[i] = '_';
            break;
        default:
            break;
        }
    }
    return 0;
}
static int base64_decode_url(const char *data, size_t data_len, std::string &raw){
    std::string base64(data, data_len);
    for(size_t i=0;i<base64.size();++i){
        switch(base64[i]){
        case '*':
            base64[i] = '+';
            break;
        case '-':
            base64[i] = '/';
            break;
        case '_':
            base64[i] = '=';
            break;
        default:
            break;
        }
    }
    return base64_decode(base64.data(), base64.size(), raw);
}

static int compress(const void *data, size_t data_len, std::string &compressed){
    compressed.resize(std::max(data_len, static_cast<size_t>(128)));
    uLongf uLen = compressed.size();
    int ret = compress2(
        reinterpret_cast<Bytef*>(const_cast<char*>(compressed.data())), &uLen,
        reinterpret_cast<const Bytef*>(data), data_len, Z_BEST_SPEED);
    if(ret == Z_OK) {
        compressed.resize(uLen);
        return ret;
    }
    if(ret != Z_MEM_ERROR)return ret;
    compressed.resize(compressed.size() * 2);
    uLen = compressed.size();
    ret = compress2(
        reinterpret_cast<Bytef*>(const_cast<char*>(compressed.data())), &uLen,
        reinterpret_cast<const Bytef*>(data), data_len, Z_BEST_SPEED);
    if(ret == Z_OK) compressed.resize(uLen);
    return ret;

}
static int uncompress(const void *data, size_t data_len, std::string &uncompressed){
    int ret;
    uncompressed.resize(data_len * 2);
    do {
        uncompressed.resize(uncompressed.size() * 2);
        uLongf uLen = uncompressed.size();
        ret = ::uncompress(reinterpret_cast<Bytef*>(const_cast<char*>(uncompressed.data())), &uLen,
                       reinterpret_cast<const Bytef*>(data), data_len);
        if (ret == Z_OK) uncompressed.resize(uLen);
    }while(ret == Z_MEM_ERROR);
    return ret;
}

static std::string Dump(const rapidjson::Value *v){
    if(v == NULL)return "(null)";
    switch(v->GetType()){
    case rapidjson::kStringType:
        return std::string(v->GetString(), v->GetStringLength());
    default:
        break;
    }
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> w(s);
    v->Accept(w);
    return std::string(s.GetString(),s.GetSize());
}

static int JsonToSig(const rapidjson::Document &json, std::string &sig, std::string &errmsg){
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> w(s);
    json.Accept(w);

    std::string compressed;
    int ret = compress(s.GetString(), s.GetSize(), compressed);
    if (ret != Z_OK)
    {
        errmsg = fmt::sprintf("compress failed %d", ret);
        return CHECK_ERR16;
    }
    ret =base64_encode_url(compressed.data(), compressed.size(), sig);
    if(ret != 0){
        errmsg = fmt::sprintf("base64_encode_url failed %#x", ret);
        return CHECK_ERR16;
    }
    return 0;
}

TLS_API int SigToJson(const std::string &sig, std::string &json, std::string  &errmsg) {
    std::string compressed;
    int ret = base64_decode_url(sig.data(), sig.size(), compressed);
    if(ret != 0){
        errmsg = fmt::sprintf("base64_decode_url failed %#x", ret);
        return CHECK_ERR2;
    }
    ret = uncompress(compressed.data(), compressed.size(), json);
    if (ret != Z_OK)
    {
        errmsg = fmt::sprintf("uncompress failed %d", ret);
        return CHECK_ERR3;
    }
    return 0;
}

static int SigToJson(const std::string &sig, rapidjson::Document &json, std::string  &errmsg){
    std::string json_text;
    int ret = SigToJson(sig, json_text, errmsg);
    if(ret != 0)return ret;
    if(json.Parse(json_text.data()).HasParseError()){
        errmsg = fmt::sprintf("parse json failed");
        return CHECK_ERR4;
    }
    return 0;
}

static int CheckJson(const rapidjson::Document& json, const std::string& req_identifier,
                     uint32_t req_appid, string& strErrMsg, uint32_t *init_time = NULL, uint32_t *expire_time = NULL, bool old_time = false)
{
    rapidjson::Pointer p_indentifier("/TLS.identifier");
    const rapidjson::Value *identifier = p_indentifier.Get(json);
    if (!identifier || !identifier->IsString() ||
        req_identifier != identifier->GetString()) {
        strErrMsg =
            fmt::sprintf("identifier not match (%s)sig and (%s)req",
                         Dump(identifier).c_str(), req_identifier.c_str());
        return CHECK_ERR13;
    }

    rapidjson::Pointer p_appid("/TLS.sdk_appid");
    const rapidjson::Value *appid = p_appid.Get(json);
    if (!appid || !appid->IsString() ||
        strtoul(appid->GetString(), NULL, 10) != req_appid) {
        strErrMsg =
            fmt::sprintf("identifier not match (%s)sig and (%u)req",
                         Dump(appid).c_str(), req_appid);
        return CHECK_ERR14;
    }

    rapidjson::Pointer p_time("/TLS.time");
    const rapidjson::Value *tim = p_time.Get(json);
    if (!tim || !tim->IsString()) {
        strErrMsg = "bad time";
        return CHECK_ERR10;
    }
    rapidjson::Pointer p_expire("/TLS.expire_after");
    const rapidjson::Value *expire = p_expire.Get(json);
    if (!expire || !expire->IsString()) {
        strErrMsg = "bad expire";
        return CHECK_ERR10;
    }
    time_t now = time(NULL);
    time_t init = atol(tim->GetString()) ;
    if(old_time){
        struct tm t;
#ifdef _XOPEN_SOURCE
		strptime(tim->GetString(), "%FT%T-08:00", &t);
#else
		std::istringstream s(tim->GetString());
		s >> std::get_time(&t, "%Y-%m-%dT%H:%M:%S-08:00");
#endif
        init = mktime(&t);
    }
    else {
        init = atol(tim->GetString()) ;
    }
    time_t timeout = atol(expire->GetString());
    if(init_time)*init_time = init;
    if(expire_time)*expire_time = timeout;
    if(init + timeout < now){
        strErrMsg = fmt::sprintf("timeout %ld + %ld < %ld", init, timeout, now);
        return CHECK_ERR9;
    }
	return 0;
}

static int JsonToUserbufSign(const rapidjson::Document &json, std::string &sign_buffer){
    if(!json.IsObject()) return -1;

    const char *pointer[] = {
        "/TLS.appid_at_3rd",
        "/TLS.account_type",
        "/TLS.identifier",
        "/TLS.sdk_appid",
        "/TLS.time",
        "/TLS.expire_after",
        "/TLS.userbuf",
    };

    for(size_t i=0;i<sizeof pointer/sizeof pointer[0];++i){
        rapidjson::Pointer p(pointer[i]);
        const rapidjson::Value *node = p.Get(json);
        if(node == NULL)return -2;
        sign_buffer.append(pointer[i] + 1)
            .append(":")
            .append(Dump(node))
            .append("\n");
    }
    return 0;
}
static int JsonToSign(const rapidjson::Document &json, std::string &sign_buffer){
    if(!json.IsObject()) return -1;

    static rapidjson::Pointer p_appid3rd("/TLS.appid_at_3rd");
    const rapidjson::Value* appid3rd = p_appid3rd.Get(json);
    if (appid3rd) {
        sign_buffer.append("TLS.appid_at_3rd:")
            .append(Dump(appid3rd))
            .append("\n");
    }
    const char *pointer[] = {
        "/TLS.account_type",
        "/TLS.identifier",
        "/TLS.sdk_appid",
        "/TLS.time",
        "/TLS.expire_after",
    };

    for(size_t i=0;i<sizeof pointer/sizeof pointer[0];++i){
        rapidjson::Pointer p(pointer[i]);
        const rapidjson::Value *node = p.Get(json);
        if(node == NULL)return -2;
        sign_buffer.append(pointer[i] + 1)
            .append(":")
            .append(Dump(node))
            .append("\n");
    }
    return 0;
}

#ifdef USE_OPENSSL
static int get_licence(char* pLicen, size_t* pLicenLen, const char* pData, uint32_t uDataLen, const string& strPrivateKey)
{
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *key = NULL;
    BIO *keybuf = NULL; 
    bool succ = false;
    keybuf = BIO_new_mem_buf(const_cast<char*>(strPrivateKey.data()), strPrivateKey.size());
    if(keybuf == NULL)goto clean;
    key = PEM_read_bio_PrivateKey(keybuf, NULL, NULL, NULL); 
    if(key == NULL)goto clean;

    if(!(mdctx = EVP_MD_CTX_create())) goto clean;
    if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key)) goto clean;
    if(1 != EVP_DigestSignUpdate(mdctx, pData, uDataLen)) goto clean;
    if(1 != EVP_DigestSignFinal(mdctx, reinterpret_cast<uint8_t*>(pLicen), pLicenLen)) goto clean;
    succ = true;
clean:
    if(mdctx)EVP_MD_CTX_destroy(mdctx);
    if(key)EVP_PKEY_free(key);
    if(keybuf)BIO_free_all(keybuf);
    if(succ)return 0;
    long ret = ERR_get_error();
    if(ret) return ret;
    return -1;
}
static int check_licence(const char* pLicen, uint32_t uLicenLen, const char* pData, uint32_t uDataLen, const string& strPublicKey)
{
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *key = NULL;
    BIO *keybuf = NULL; 
    bool succ = false;
    keybuf = BIO_new_mem_buf(const_cast<char*>(strPublicKey.data()), strPublicKey.size());
    if(keybuf == NULL)goto clean;
    key = PEM_read_bio_PUBKEY(keybuf, NULL, NULL, NULL); 
    if(key == NULL)goto clean;

    if(!(mdctx = EVP_MD_CTX_create())) goto clean;
    if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, key)) goto clean;
    if(1 != EVP_DigestVerifyUpdate(mdctx, pData, uDataLen)) goto clean;
    if(1 != EVP_DigestVerifyFinal(mdctx, const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(pLicen)), uLicenLen)) goto clean;
    succ = true;
clean:
    if(mdctx)EVP_MD_CTX_destroy(mdctx);
    if(key)EVP_PKEY_free(key);
    if(keybuf)BIO_free_all(keybuf);
    if(succ)return 0;
    long ret = ERR_get_error();
    if(ret) return ret;
    return -1;
}
#else
static int get_licence(char* pLicen, size_t* pLicenLen, const char* pData, uint32_t uDataLen, const string& strPrivateKey)
{
	int iRet = 0;
	unsigned char hash[32];
	mbedtls_pk_context ctx;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_pk_init(&ctx);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	iRet = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
	if (iRet != 0) {
		goto end;
	}
	iRet = mbedtls_pk_parse_key(&ctx, reinterpret_cast<const unsigned char*>(strPrivateKey.data()), strPrivateKey.size()+1, NULL, 0);
	if (iRet != 0) {
		goto end;
	}
	iRet = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), reinterpret_cast<const unsigned char*>(pData), uDataLen, hash);
	if (iRet != 0) {
		goto end;
	}
	iRet = mbedtls_pk_sign(&ctx, MBEDTLS_MD_SHA256, hash, 0, reinterpret_cast<unsigned char*>(pLicen), pLicenLen, mbedtls_ctr_drbg_random, &ctr_drbg);
	if (iRet != 0) {
		goto end;
	}
end:
	mbedtls_pk_free(&ctx);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return iRet;
}

static int check_licence(const char* pLicen, uint32_t uLicenLen, const char* pData, uint32_t uDataLen, const string& strPublicKey)
{
	int iRet = 0;
	unsigned char hash[32];
	mbedtls_pk_context ctx;
	mbedtls_pk_init(&ctx);
	iRet = mbedtls_pk_parse_public_key(&ctx, reinterpret_cast<const unsigned char*>(strPublicKey.data()), strPublicKey.size()+1);
	if (iRet != 0) {
		goto end;
	}
	iRet = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), reinterpret_cast<const unsigned char*>(pData), uDataLen, hash);
	if (iRet != 0) {
		goto end;
	}
	iRet = mbedtls_pk_verify(&ctx, MBEDTLS_MD_SHA256, hash, 0, reinterpret_cast<const unsigned char*>(pLicen), uLicenLen);
	if (iRet != 0) {
		goto end;
	}
end:
	mbedtls_pk_free(&ctx);
	return iRet;
}
#endif

static int tls_check_signature_inner(
		const rapidjson::Document &json,
        const std::string strPubKey,
		string& strErrMsg)
{
    std::string content;
    int ret = JsonToSign(json, content);
    if(ret != 0){
        strErrMsg = "json bad format";
        return CHECK_ERR4;
    }

    rapidjson::Document::ConstMemberIterator sig = json.FindMember("TLS.sig");
    if(sig == json.MemberEnd() || !sig->value.IsString()) {
        return CHECK_ERR7;
    }
    std::string raw_sig;
    ret = base64_decode(sig->value.GetString(), sig->value.GetStringLength(), raw_sig);
    if(ret != 0){
        return CHECK_ERR6;
    }
    ret = check_licence(raw_sig.data(), raw_sig.size(), content.data(), content.size(), strPubKey);
    if(ret != 0){
        return CHECK_ERR8;
    }

	return 0;
}
}

using namespace tls_signature_inner;

TLS_API int tls_gen_signature(const string& strJson,string& strSig,const char* pPriKey,uint32_t uPriKeyLen,string& strErrMsg,uint32_t dwFlag)
{
	char pLicen[1024];
	size_t LicenLen = sizeof(pLicen);
	string strSerial;
	time_t Time = time(NULL);
#if defined(WIN32) || defined(WIN64)
	struct tm stTm;
    localtime_s(&stTm,&Time);
	struct tm* pstTm = &stTm;
#else
	struct tm* pstTm = localtime(&Time);
#endif
	char TimeBuf[256] = {0};
	if (dwFlag == TIME_UT_FORM) {
		snprintf(TimeBuf,sizeof(TimeBuf), "%u",(uint32_t)Time);
	} else {
		snprintf(TimeBuf,sizeof(TimeBuf),"%04d-%02d-%02dT%02d:%02d:%02d-08:00"
				,pstTm->tm_year + 1900,pstTm->tm_mon+1,pstTm->tm_mday,pstTm->tm_hour,pstTm->tm_min,pstTm->tm_sec);
	}	
    rapidjson::Document json;
    if(json.Parse(strJson.c_str()).HasParseError()){
        strErrMsg = "json decode failed";
        return CHECK_ERR4;
    }
    json.AddMember("TLS.time", rapidjson::StringRef(TimeBuf), json.GetAllocator());
	int iRet = JsonToSign(json,strSerial);
	if (iRet != 0)
	{
        strErrMsg = fmt::sprintf("json decode failed:%d", iRet);
        return CHECK_ERR4;
	}

	iRet = get_licence(pLicen,&LicenLen,strSerial.c_str(),strSerial.length(),string(pPriKey,uPriKeyLen));
	if (iRet != 0) 
	{
        strErrMsg = fmt::sprintf("get_licence err code:%d",iRet);
		return CHECK_ERR17;
	}
    std::string ticket;
    iRet = base64_encode(pLicen, LicenLen, ticket);
    if(iRet != 0){
        strErrMsg = fmt::printf("base64_encode failed:%#x", iRet);
        return CHECK_ERR16;
    }
    json.AddMember("TLS.sig", ticket, json.GetAllocator());

	if (dwFlag == TIME_UT_FORM) {	
        return JsonToSig(json, strSig, strErrMsg);
	}
    else {
        strSig = Dump(&json);
    }
	return 0;
}

TLS_API int tls_check_signature_ex(
    const string& strSig,
    const char* pPubKey,
    uint32_t uPubKeyLen,
    const SigInfo& stSigInfo,
    uint32_t& dwExpireTime,
    uint32_t& dwInitTime,
    string& strErrMsg)
{
	if (strSig.empty()) {
		strErrMsg = "strSig empty";
		return CHECK_ERR1;
	}

    rapidjson::Document json;
    int ret = 0;
	if (!json.Parse(strSig.c_str()).HasParseError()) {
		ret = tls_check_signature_inner(json,std::string(pPubKey,uPubKeyLen),strErrMsg);
        if (ret != 0) return ret;
        return CheckJson(json, stSigInfo.strIdentify,
                         strtoul(stSigInfo.strAppid.c_str(), NULL, 10),
                         strErrMsg, &dwInitTime, &dwExpireTime, true);
    } else {
        ret = SigToJson(strSig, json, strErrMsg);
        if (ret != 0) return ret;
		ret = tls_check_signature_inner(json,std::string(pPubKey,uPubKeyLen), strErrMsg);
        if (ret != 0) return ret;
        return CheckJson(json, stSigInfo.strIdentify,
                         strtoul(stSigInfo.strAppid.c_str(), NULL, 10),
                         strErrMsg, &dwInitTime, &dwExpireTime);
    }
	return 0;
}

TLS_API int tls_check_signature_ex2(
    const string& strSig,
    const string& strPubKey,
    uint32_t dwSdkAppid,
    const string& strIdentifier,
    uint32_t& dwExpireTime,
    uint32_t& dwInitTime,
    string& strErrMsg)
{
    SigInfo sigInfo;
    sigInfo.strAccountType = "0";
    sigInfo.strAppid3Rd = "0";
    sigInfo.strIdentify = strIdentifier;
    sigInfo.strAppid = fmt::sprintf("%u", dwSdkAppid);

    return tls_check_signature_ex(strSig, strPubKey.data(), strPubKey.size(), sigInfo, dwExpireTime, dwInitTime, strErrMsg);
}

TLS_API int tls_gen_signature_ex(
    uint32_t dwExpire,
    const string& strAppid3rd,
    uint32_t dwSdkAppid,
    const string& strIdentifier,
    uint32_t dwAccountType,
    string& strSig,
    const char* pPriKey,
    uint32_t uPriKeyLen,
    string& strErrMsg)
{
	char buff[512];
	int iLen = snprintf(buff,sizeof(buff),JSON_STRING
			,dwAccountType,strIdentifier.c_str()
			,strAppid3rd.c_str(),dwSdkAppid,dwExpire
			,API_VERSION);
	if (iLen >= (int)(sizeof(buff) - 1)) {
		snprintf(buff,sizeof(buff),"gen sig buf is empty iLen:%d",iLen);
		strErrMsg = buff;
		return -1;
	}
	string strJson = buff; 
	return tls_gen_signature(strJson,strSig,pPriKey,uPriKeyLen,strErrMsg,TIME_UT_FORM);
}

// 带有效期生成 sig 的接口
TLS_API int tls_gen_signature_ex2_with_expire(
    uint32_t dwSdkAppid,
    const string& strIdentifier,
    uint32_t dwExpire,
    string& strSig,
    string& strPriKey,
    string& strErrMsg)
{
	char buff[512];
	int iLen = snprintf(buff, sizeof(buff), JSON_STRING, 0, strIdentifier.c_str(), "0", dwSdkAppid, dwExpire, API_VERSION);
	if (iLen >= (int)(sizeof(buff) - 1)) {
		snprintf(buff,sizeof(buff),"gen sig buf is empty iLen:%d",iLen);
		strErrMsg = buff;
		return -1;
	}
	string strJson = buff; 
    int ret = tls_gen_signature(
        strJson, strSig, const_cast<char *>(strPriKey.c_str()),
        strPriKey.size(), strErrMsg, TIME_UT_FORM);
	return ret;
}

// 简化版生成 sig 的接口
TLS_API int tls_gen_signature_ex2(
    uint32_t dwSdkAppid,
    const string& strIdentifier,
    string& strSig,
    string& strPriKey,
    string& strErrMsg)
{
    return tls_gen_signature_ex2_with_expire(
        dwSdkAppid, strIdentifier, DEFAULT_EXPIRE, strSig, strPriKey, strErrMsg);
}

TLS_API int tls_gen_userbuf_ticket(
    uint32_t dwSdkAppid,
    const std::string& strIdentifier,
    uint32_t dwExpire,
    const std::string& strPriKey,
    const std::string& strUserbuf,
    std::string& strTicket,
    std::string& strErrMsg){
    rapidjson::Document json;
    json.SetObject();
    json.AddMember("TLS.sdk_appid", fmt::sprintf("%u" ,dwSdkAppid), json.GetAllocator());
    json.AddMember("TLS.identifier", strIdentifier, json.GetAllocator());
    json.AddMember("TLS.time", fmt::sprintf("%ld", time(NULL)), json.GetAllocator());
    json.AddMember("TLS.expire_after", fmt::sprintf("%u", dwExpire), json.GetAllocator());
    json.AddMember("TLS.account_type", "0", json.GetAllocator());
    json.AddMember("TLS.appid_at_3rd", "0", json.GetAllocator());
    std::string base64_userbuf;
    int ret = base64_encode(strUserbuf.data(), strUserbuf.size(), base64_userbuf);
    if(ret != 0){
        strErrMsg = fmt::printf("base64_encode failed:%#x", ret);
        return CHECK_ERR16;
    }
    json.AddMember("TLS.userbuf", base64_userbuf, json.GetAllocator());
    std::string content;
    ret = JsonToUserbufSign(json, content);
    if (ret != 0) {
        strErrMsg = "invalid json object";
        return CHECK_ERR16;
    }
    uint8_t bin_ticket[1024*16];
    size_t bin_ticket_len = sizeof bin_ticket;
    ret = get_licence(reinterpret_cast<char*>(bin_ticket), &bin_ticket_len, content.data(), content.size(), strPriKey);
    if(ret != 0){
        strErrMsg = fmt::printf("get_licence failed:%#x", ret);
        return CHECK_ERR17;
    }
    std::string ticket;
    ret = base64_encode(bin_ticket, bin_ticket_len, ticket);
    if(ret != 0){
        strErrMsg = fmt::printf("base64_encode failed:%#x", ret);
        return CHECK_ERR16;
    }
    json.AddMember("TLS.sig", ticket, json.GetAllocator());
    return JsonToSig(json, strTicket, strErrMsg);
}

TLS_API int tls_check_userbuf_ticket(
    const std::string& strTicket,
    const std::string& strPubKey,
    uint32_t dwSdkAppid,
    const std::string& strIdentifier,
    uint32_t& dwExpireTime,
    uint32_t& dwInitTime,
    std::string& strUserbuf,
    std::string& strErrMsg){
    rapidjson::Document json;
    int ret = SigToJson(strTicket, json, strErrMsg);
    if (ret != 0) return ret;
    std::string content;
    ret = JsonToUserbufSign(json ,content);
    if (ret != 0) {
        return CHECK_ERR4;
    }
    rapidjson::Document::MemberIterator sig = json.FindMember("TLS.sig");
    if(sig == json.MemberEnd() || !sig->value.IsString()) {
        return CHECK_ERR7;
    }
    std::string raw_sig;
    ret = base64_decode(sig->value.GetString(), sig->value.GetStringLength(), raw_sig);
    if(ret != 0){
        return CHECK_ERR6;
    }
    ret = ::check_licence(raw_sig.data(), raw_sig.size(), content.data(), content.size(), strPubKey);
    if(ret != 0){
        return CHECK_ERR8;
    }
    ret = ::CheckJson(json, strIdentifier, dwSdkAppid, strErrMsg, &dwInitTime, &dwExpireTime);
    if(ret != 0){
        return ret;
    }
    rapidjson::Document::MemberIterator user = json.FindMember("TLS.userbuf");
    if(!user->value.IsString()) {
        strErrMsg = "userbuf is not string";
        return CHECK_ERR15;
    }
    ret = base64_decode(user->value.GetString(), user->value.GetStringLength(), strUserbuf);
    if(ret != 0){
        strErrMsg = fmt::sprintf("base64 decode userbuf error:%#x", ret);
        return CHECK_ERR15;
    }
    return 0;
}
