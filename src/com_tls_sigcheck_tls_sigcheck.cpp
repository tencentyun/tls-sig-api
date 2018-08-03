#include "com_tls_sigcheck_tls_sigcheck.h"

#include <stdlib.h>

#include "tls_signature.h"

using namespace std;

JNIEXPORT jint JNICALL Java_com_tls_sigcheck_tls_1sigcheck_tls_1gen_1signature_1ex
  (JNIEnv* env, jobject thiz, jstring strExpire, jstring strAppid3rd, jstring strSdkAppid, jstring strIdentifier, jstring strAccountType, jstring strPriKey)
{
	jclass clazz = env->GetObjectClass(thiz);

	const char* expire_after = (const char*)env->GetStringUTFChars(strExpire, false);
	uint32_t dwExpire = strtoul(expire_after,NULL,10);

	const char* appid3rd  = (const char*)env->GetStringUTFChars(strAppid3rd, false);
	uint32_t appid3rdlen = env->GetStringUTFLength(strAppid3rd);
	string stringAppid3rd; stringAppid3rd.assign(appid3rd,appid3rdlen);
	
	const char* sdkappid = (const char*)env->GetStringUTFChars(strSdkAppid, false);
	uint32_t dwSdkAppid = strtoul(sdkappid,NULL,10);
	
	const char* id  = (const char*)env->GetStringUTFChars(strIdentifier, false);
	uint32_t idlen = env->GetStringUTFLength(strIdentifier);
	string stringIdentifier; stringIdentifier.assign(id,idlen);

	const char* accounttype = (const char*)env->GetStringUTFChars( strAccountType, false);
	uint32_t dwAccountType = strtoul(accounttype,NULL,10);
	
	const char* skey_ptr = (const char*)env->GetStringUTFChars(strPriKey, false);
	int skey_len = env->GetStringUTFLength(strPriKey);
	
	string stringErrMsg;string stringSig;
	int iRet = tls_gen_signature_ex(dwExpire, stringAppid3rd
			, dwSdkAppid, stringIdentifier 
			, dwAccountType, stringSig
			, (char*)skey_ptr,skey_len, stringErrMsg);
	
	jfieldID JsonSigfid = env->GetFieldID(clazz, "strJsonWithSig", "Ljava/lang/String;");
	env->SetObjectField(thiz, JsonSigfid, env->NewStringUTF(stringSig.c_str()));

	jfieldID ErrMsg = env->GetFieldID(clazz, "strErrMsg", "Ljava/lang/String;");
	env->SetObjectField(thiz, ErrMsg, env->NewStringUTF(stringErrMsg.c_str()));

	return iRet;
}
JNIEXPORT jint JNICALL Java_com_tls_sigcheck_tls_1sigcheck_tls_1gen_1signature
  (JNIEnv * env, jobject thiz, jstring strJson, jstring strPriKey)
{
	jclass clazz = env->GetObjectClass(thiz);

	const char* skey_ptr = (const char*)env->GetStringUTFChars(strPriKey, false);
	int skey_len = env->GetStringUTFLength(strPriKey);
	string stringPKey; stringPKey.assign(skey_ptr,skey_len);

	const char* pJson = (const char*)env->GetStringUTFChars(strJson, false);
	int iJsonLen = env->GetStringUTFLength(strJson);
	string stringJson; stringJson.assign(pJson,iJsonLen);

	string stringErrMsg; string stringJsonWithSig;
	int iRet = tls_gen_signature(stringJson,stringJsonWithSig,(char* )(stringPKey.c_str()),stringPKey.length(), stringErrMsg);


	jfieldID JsonSigfid = env->GetFieldID(clazz, "strJsonWithSig", "Ljava/lang/String;");
	env->SetObjectField(thiz, JsonSigfid, env->NewStringUTF(stringJsonWithSig.c_str()));

	jfieldID ErrMsg = env->GetFieldID(clazz, "strErrMsg", "Ljava/lang/String;");
	env->SetObjectField(thiz, ErrMsg, env->NewStringUTF(stringErrMsg.c_str()));
	return iRet;
}

JNIEXPORT jint JNICALL Java_com_tls_sigcheck_tls_1sigcheck_tls_1check_1signature_1ex
  (JNIEnv* env, jobject thiz, jstring strJsonWithSig, jstring strPubKey
, jstring strAccountType, jstring str3rd, jstring strAppid,jstring strIdentify)
{
	jclass clazz = env->GetObjectClass(thiz);

	const char* skey_ptr = (const char*)env->GetStringUTFChars(strPubKey, false);
	int skey_len = env->GetStringUTFLength(strPubKey);
	string stringPKey; stringPKey.assign(skey_ptr,skey_len);

	const char* pJson = (const char*)env->GetStringUTFChars(strJsonWithSig, false);
	int iJsonLen = env->GetStringUTFLength(strJsonWithSig);
	string stringJsonWithSig; 
	stringJsonWithSig.assign(pJson,iJsonLen);

	SigInfo stSigInfo;	
	const char* pAccountType = (const char*)env->GetStringUTFChars(strAccountType, false);
	int iAccountLen = env->GetStringUTFLength(strAccountType);
	string stringAccountType; 
	stringAccountType.assign(pAccountType,iAccountLen);
	stSigInfo.strAccountType = stringAccountType;

	const char* pAppid3rd = (const char*)env->GetStringUTFChars(str3rd, false);
	int iAppid3rdLen = env->GetStringUTFLength(str3rd);
	string stringAppid3rd; 
	stringAppid3rd.assign(pAppid3rd,iAppid3rdLen);
	stSigInfo.strAppid3Rd = stringAppid3rd;

	const char* pAppid = (const char*)env->GetStringUTFChars(strAppid, false);
	int iAppidLen = env->GetStringUTFLength(strAppid);
	string stringAppid; 
	stringAppid.assign(pAppid,iAppidLen);
	stSigInfo.strAppid = stringAppid;
	
	const char* pIdentify = (const char*)env->GetStringUTFChars(strIdentify, false);
	int iIdentifyLen = env->GetStringUTFLength(strIdentify);
	string stringIdentify; 
	stringIdentify.assign(pIdentify,iIdentifyLen);
	stSigInfo.strIdentify = stringIdentify;
	
	string stringErrMsg;
	uint32_t iExpireTime;
	uint32_t iInitTime;
	int iRet = tls_check_signature_ex(stringJsonWithSig,(char* )(stringPKey.c_str()),stringPKey.length()
		,stSigInfo, iExpireTime, iInitTime, stringErrMsg);

	jfieldID ErrMsg = env->GetFieldID(clazz, "strErrMsg", "Ljava/lang/String;");
	env->SetObjectField(thiz, ErrMsg, env->NewStringUTF(stringErrMsg.c_str()));
	return iRet;
}

JNIEXPORT jint JNICALL Java_com_tls_sigcheck_tls_1sigcheck_tls_1gen_1signature_1ex2
  (JNIEnv * env, jobject thiz, jstring jstrSdkAppid, jstring jstrIdentifier, jstring jstrPriKey)
{
	jclass clazz = env->GetObjectClass(thiz);
	
	const char * pSdkAppid = env->GetStringUTFChars(jstrSdkAppid, false);
	uint32_t sdkAppid = strtoul(pSdkAppid, NULL, 10);
	
	const char* pIdentifier  = env->GetStringUTFChars(jstrIdentifier, false);
	int identifierLen = env->GetStringUTFLength(jstrIdentifier);
	string identifier(pIdentifier, identifierLen);
	
	const char * pPriKey = (const char*)env->GetStringUTFChars(jstrPriKey, false);
	int priKeyLen = env->GetStringUTFLength(jstrPriKey);
    string priKey(pPriKey, priKeyLen);
	
	string errMsg;
    string userSig;
	int ret = tls_gen_signature_ex2(sdkAppid, identifier, userSig, priKey, errMsg);
	
	jfieldID userSigId = env->GetFieldID(clazz, "strJsonWithSig", "Ljava/lang/String;");
	env->SetObjectField(thiz, userSigId, env->NewStringUTF(userSig.c_str()));

	jfieldID errMsgId = env->GetFieldID(clazz, "strErrMsg", "Ljava/lang/String;");
	env->SetObjectField(thiz, errMsgId, env->NewStringUTF(errMsg.c_str()));

	return ret;
}

JNIEXPORT jint JNICALL Java_com_tls_sigcheck_tls_1sigcheck_tls_1gen_1signature_1ex2_1with_1expire
  (JNIEnv * env, jobject thiz, jstring jstrSdkAppid, jstring jstrIdentifier, jstring jstrPriKey, jstring jstrExpire)
{
	jclass clazz = env->GetObjectClass(thiz);
	
	const char * pSdkAppid = env->GetStringUTFChars(jstrSdkAppid, false);
	uint32_t sdkAppid = strtoul(pSdkAppid, NULL, 10);
	
	const char* pIdentifier  = env->GetStringUTFChars(jstrIdentifier, false);
	int identifierLen = env->GetStringUTFLength(jstrIdentifier);
	string identifier(pIdentifier, identifierLen);
	
	const char * pPriKey = (const char*)env->GetStringUTFChars(jstrPriKey, false);
	int priKeyLen = env->GetStringUTFLength(jstrPriKey);
    string priKey(pPriKey, priKeyLen);
	
	const char * pExpire = env->GetStringUTFChars(jstrExpire, false);
	uint32_t expire = strtoul(pExpire, NULL, 10);

	string errMsg;
    string userSig;
	int ret = tls_gen_signature_ex2_with_expire(sdkAppid, identifier, expire, userSig, priKey, errMsg);
	
	jfieldID userSigId = env->GetFieldID(clazz, "strJsonWithSig", "Ljava/lang/String;");
	env->SetObjectField(thiz, userSigId, env->NewStringUTF(userSig.c_str()));

	jfieldID errMsgId = env->GetFieldID(clazz, "strErrMsg", "Ljava/lang/String;");
	env->SetObjectField(thiz, errMsgId, env->NewStringUTF(errMsg.c_str()));

	return ret;
}

JNIEXPORT jint JNICALL Java_com_tls_sigcheck_tls_1sigcheck_tls_1check_1signature_1ex2
  (JNIEnv * env, jobject thiz, jstring jstrUserSig, jstring jstrPubKey, jstring jstrSdkAppid, jstring jstrIdentifier)
{
    jclass clazz = env->GetObjectClass(thiz);

	const char * pUserSig = (const char*)env->GetStringUTFChars(jstrUserSig, false);
	int userSigLen = env->GetStringUTFLength(jstrUserSig);
	string userSig(pUserSig, userSigLen);

	const char * pPubKey = env->GetStringUTFChars(jstrPubKey, false);
	int pubKeyLen = env->GetStringUTFLength(jstrPubKey);
	string pubKey(pPubKey, pubKeyLen);
    
	const char * pSdkAppid = env->GetStringUTFChars(jstrSdkAppid, false);
	uint32_t sdkAppid = strtoul(pSdkAppid, NULL, 10);
    
    const char* pIdentifier  = env->GetStringUTFChars(jstrIdentifier, false);
	int identifierLen = env->GetStringUTFLength(jstrIdentifier);
	string identifier(pIdentifier, identifierLen);
    
    uint32_t expire_time;
    uint32_t init_time;
    string errMsg;
    int ret;
    
    ret = tls_check_signature_ex2(
        userSig, pubKey, sdkAppid, identifier, expire_time, init_time, errMsg);

	jfieldID errMsgId = env->GetFieldID(clazz, "strErrMsg", "Ljava/lang/String;");
    jfieldID expireTimeId = env->GetFieldID(clazz, "expireTime", "I");
    jfieldID initTimeId = env->GetFieldID(clazz, "initTime", "I");
    
    env->SetIntField(thiz, expireTimeId, expire_time);
    env->SetIntField(thiz, initTimeId, init_time);
	env->SetObjectField(thiz, errMsgId, env->NewStringUTF(errMsg.c_str()));

	return ret;
}
