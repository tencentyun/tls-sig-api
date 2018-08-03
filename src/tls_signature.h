#ifndef  CHECK_LICENCE_H
#define  CHECK_LICENCE_H

#if defined(WIN32) || defined(WIN64)
#pragma warning(disable: 4819)			// file codec warning, that's boring!
#define TLS_API __declspec(dllexport)
#else
#define TLS_API
#endif

#include <stdint.h>

#include <string>

/*
 * tls_gen_signature_ex ����һϵ�в��������� sig
 *
 * @param dwExpire ����ʱ��������Ϊ��λ�����鲻����һ���£����ǩ����Ч��Ϊ 10 �죬�Ǿ��� 10*24*3600
 * @param strAppid3Rd ����������ƽ̨�˺� appid����������е��˺ţ���ôֱ���� sdkappid ���ַ�����ʽ
 * @param dwSdkAppid ����Ӧ��ʱҳ���Ϸ���� sdkappid
 * @param strIdentifier �û���ʾ����Ҳ�������ǳ�˵���û� id
 * @param dwAccountType ����Ӧ��ʱҳ���Ϸ���� accounttype
 * @param strSig ���ص� sig
 * @param pPriKey ˽Կ���ݣ���ע�ⲻ��˽Կ�ļ���
 * @param uPriKeyLen ˽Կ���ݳ���
 * @param strErrMsg ����������������Ϣ
 *
 * @return 0 ��ʾ�ɹ����� 0 ��ʾʧ�ܣ�ʧ����Ϣ���� strErrMsg �и���
 */
TLS_API int tls_gen_signature_ex(
    uint32_t dwExpire,
    const std::string& strAppid3Rd,
    uint32_t dwSdkAppid,
    const std::string& strIdentifier,
    uint32_t dwAccountType,
    std::string& strSig,
    const char* pPriKey,
    uint32_t uPriKeyLen,
    std::string& strErrMsg
);

/*
 * @brief tls_gen_signature_ex2_with_expire ����һϵ�в��������� sig
 *
 * @param dwSdkAppid ����Ӧ��ʱҳ���Ϸ���� sdkappid
 * @param strIdentifier �û���ʾ����Ҳ�������ǳ�˵���û� id
 * @param dwExpire �������Զ������Ч�ڣ���λ���룬�Ƽ�ʱ��Ϊ 1 ����
 * @param strSig ���ص� sig
 * @param strPriKey ˽Կ���ݣ���ע�ⲻ��˽Կ�ļ���
 * @param strErrMsg ����������������Ϣ
 *
 * @return 0 ��ʾ�ɹ����� 0 ��ʾʧ�ܣ�ʧ����Ϣ���� strErrMsg �и���
 */
TLS_API int tls_gen_signature_ex2_with_expire(
    uint32_t dwSdkAppid,
    const std::string& strIdentifier,
    uint32_t dwExpire,
    std::string& strSig,
    std::string& strPriKey,
    std::string& strErrMsg);

/*
 * @brief tls_gen_signature_ex2 ����һϵ�в��������� sig����Ч����Ĭ�ϵ�180��
 *
 * @param dwSdkAppid ����Ӧ��ʱҳ���Ϸ���� sdkappid
 * @param strIdentifier �û���ʾ����Ҳ�������ǳ�˵���û� id
 * @param strSig ���ص� sig
 * @param strPriKey ˽Կ���ݣ���ע�ⲻ��˽Կ�ļ���
 * @param strErrMsg ����������������Ϣ
 *
 * @return 0 ��ʾ�ɹ����� 0 ��ʾʧ�ܣ�ʧ����Ϣ���� strErrMsg �и���
 */
TLS_API int tls_gen_signature_ex2(
    uint32_t dwSdkAppid,
    const std::string& strIdentifier,
    std::string& strSig,
    std::string& strPriKey,
    std::string& strErrMsg    
);

/**
 * @brief ���� sig ���ݵĽṹ�壬�����ֶεĺ�����Բο� tls_gen_signature_ex()
 * @see tls_gen_signature_ex()
 */
typedef struct
{
	std::string strAccountType;
	std::string strAppid3Rd;
	std::string strAppid;            /**< �� sdkappid  */
	std::string strIdentify;
} SigInfo;

/**
 * @brief ��֤ sig �Ƿ�Ϸ�
 *
 * @param strSig sig ������
 * @param pPubKey ��Կ�����ݣ�ע�ⲻ�ǹ�Կ�ļ���·��
 * @param uPubKeyLen ��Կ���ݵĳ���
 * @param stSigInfo sig �Ļ�����Ϣ����Ϊ sig ��֤�Ϸ��Ե�ԭ����ʹ�ù�Կ���ܣ���֤�����ֶ��������е��ֶ��Ƿ�ƥ��
 * @param dwExpireTime ���� sig ����Ч��
 * @param dwInitTime ���� sig ������ʱ��
 * @param strErrMsg ������������д�����Ϣ
 *
 * @return 0 ��ʾ�ɹ����� 0 ��ʾʧ�ܣ�strErrMsg ����ʧ����Ϣ
 */
TLS_API int tls_check_signature_ex(
    const std::string& strSig,
    const char* pPubKey,
    uint32_t uPubKeyLen,
    const SigInfo& stSigInfo,
    uint32_t& dwExpireTime,
    uint32_t& dwInitTime,
    std::string& strErrMsg
);

/**
 * @brief ��֤ sig �Ƿ�Ϸ�
 *
 * @param strSig sig ������
 * @param strPubKey ��Կ������
 * @param dwSdkAppid Ӧ�õ� sdkappid
 * @param strIdentifier �û�id������ sig �е�ֵ���жԱ�
 * @param dwExpireTime ���� sig ����Ч��
 * @param dwInitTime ���� sig ������ʱ��
 * @param strErrMsg ������������д�����Ϣ
 *
 * @return 0 ��ʾ�ɹ����� 0 ��ʾʧ�ܣ�strErrMsg ����ʧ����Ϣ
 */
TLS_API int tls_check_signature_ex2(
    const std::string& strSig,
    const std::string& strPubKey,
    uint32_t dwSdkAppid,
    const std::string& strIdentifier,
    uint32_t& dwExpireTime,
    uint32_t& dwInitTime,
    std::string& strErrMsg
);

/**
 * @brief ���� sig���˺����ѡ����Ƽ���ʹ��
 * @see tls_check_signature_ex()
 *
 * @param strJson ��������� json ��
 * strJson ʾ��
 * {
 *     "TLS.account_type": "107",
 *     "TLS.appid_at_3rd": "150000000",
 *     "TLS.identity": "xxx_openid",
 *     "TLS.sdk_appid": "150000000",
 *     "TLS.expire_after": "86400"
 * }
 * ֵ��˵������ TLS.appid_at_3rd��������ǵ���������ƽ̨���˺ţ���ô����ֶ���д�� TLS.sdk_appid һ�¾Ϳ����ˡ�
 * @param strSig ���� sig ������
 * @param pPriKey ˽Կ���ݣ�ע�ⲻ��˽Կ�ļ���·��
 * @param uPriKeyLen ˽Կ���ݵĳ���
 * @param strErrMsg ������������г�����Ϣ
 * @param dwFlag Ϊʱ���ʽ��ĿǰĬ�ϼ���
 *
 * @return ���� 0 ��ʾ�ɹ����� 0 ʧ�ܣ�strErrMsg �г�����Ϣ
 */
TLS_API int tls_gen_signature(
    const std::string& strJson,
    std::string& strSig,
    const char* pPriKey,
    uint32_t uPriKeyLen,
    std::string& strErrMsg,
    uint32_t dwFlag = 0
    );

enum {
	CHECK_ERR1  =  1,       // sig Ϊ��
	CHECK_ERR2 ,            // sig base64 ����ʧ��
	CHECK_ERR3 ,            // sig zip ��ѹ��ʧ��
	CHECK_ERR4 ,            // sig ʹ�� json ����ʱʧ��
	CHECK_ERR5 ,            // sig ʹ�� json ����ʱʧ��
	CHECK_ERR6 ,            // sig �� json �� sig �ֶ� base64 ����ʧ��
	CHECK_ERR7 ,            // sig �� json �� sig �ֶ�Ϊ��
	CHECK_ERR8 ,            // sig У��ǩ��ʧ�ܣ�һ���ǹ�˽Կ��ƥ����ɵ�
	CHECK_ERR9 ,            // sig ����
	CHECK_ERR10 ,           // sig ʹ�� json ����ʱʧ��
	CHECK_ERR11 ,           // sig �� appid_at_3rd �����Ĳ�ƥ��
	CHECK_ERR12 ,           // sig �� acctype �����Ĳ�ƥ��
	CHECK_ERR13 ,           // sig �� identifier �����Ĳ�ƥ��
	CHECK_ERR14 ,           // sig �� sdk_appid �����Ĳ�ƥ��
    CHECK_ERR15 ,           // sig �� userbuf �쳣
    CHECK_ERR16 ,           // �ڲ�����
    CHECK_ERR17 ,           // ǩ��ʧ�� ������˽Կ����

	CHECK_ERR_MAX,
};

#define API_VERSION "201803230000"

/*
 * @brief tls_gen_userbuf_ticket
 *
 * @param dwSdkAppid ����Ӧ��ʱҳ���Ϸ���� sdkappid
 * @param strIdentifier �û���ʾ����Ҳ�������ǳ�˵���û� id
 * @param dwExpire �������Զ������Ч�ڣ���λ����
 * @param strSig ���ص� sig
 * @param strPriKey ˽Կ���ݣ���ע�ⲻ��˽Կ�ļ���
 * @param strUserbuf �û��Զ�������
 * @param strErrMsg ����������������Ϣ
 *
 * @return 0 ��ʾ�ɹ����� 0 ��ʾʧ�ܣ�ʧ����Ϣ���� strErrMsg �и���
 */
TLS_API int tls_gen_userbuf_ticket(
    uint32_t dwSdkAppid,
    const std::string& strIdentifier,
    uint32_t dwExpire,
    const std::string& strPriKey,
    const std::string& strUserbuf,
    std::string& strTicket,
    std::string& strErrMsg);

/**
 * @brief ��֤ sig �Ƿ�Ϸ�
 *
 * @param strSig sig ������
 * @param strPubKey ��Կ������
 * @param dwSdkAppid Ӧ�õ� sdkappid
 * @param strIdentifier �û�id������ sig �е�ֵ���жԱ�
 * @param dwExpireTime ���� sig ����Ч��
 * @param dwInitTime ���� sig ������ʱ��
 * @param strUserbuf ��������ʱ��userbuf
 * @param strErrMsg ������������д�����Ϣ
 *
 * @return 0 ��ʾ�ɹ����� 0 ��ʾʧ�ܣ�strErrMsg ����ʧ����Ϣ
 */
TLS_API int tls_check_userbuf_ticket(
    const std::string& strTicket,
    const std::string& strPubKey,
    uint32_t dwSdkAppid,
    const std::string& strIdentifier,
    uint32_t& dwExpireTime,
    uint32_t& dwInitTime,
    std::string& strUserbuf,
    std::string& strErrMsg
);

namespace tls_signature_inner {
TLS_API int SigToJson(const std::string &sig, std::string &json, std::string  &errmsg);
}

#endif
