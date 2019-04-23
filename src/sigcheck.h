#ifndef SIGCHECK_H
#define SIGCHECK_H

#ifdef __cplusplus
extern "C" {
#endif
/**
 * 此头文件接口为 C 样式的接口，目前在 vs 工程有 dll 版本。
 * C# 已经在使用下面的接口了，如果其他语言有需要另行增加。
 */

/**
 * 生成 sig 的接口，“已不推荐使用”
 *
 * @param expire sig 有效期，以秒为单位
 * @param appid3rd 独立模式下填写与 sdkappid 的字符串形式，不可空缺
 * @param sdkappid 创建应用时页面上分配的 sdkappid
 * @param identifier 用户标识符，也就是用户 id，独立模式下，可以由开发者随意定义
 * @param acctype 账号类型，在应用管理页面上上传公钥之后，可以获取到 accounttype
 * @param pri_key 私钥内容，注意不是私钥文件的路径
 * @param pri_key_len 私钥内容长度
 * @param err_msg 出错信息，如果错误，这里有出错信息
 * @param err_msg_buff_len 出息信息缓冲区长度
 * 
 * @return 0 为成功，非 0 失败，出错信息在 err_msg 中
 */
#if defined(WIN32) || defined(WIN64)
__declspec(dllexport)
#endif
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
);

/**
 * 验证 sig 接口，“已不推荐使用”
 *
 * @param sig sig 的内容，以空字符结尾
 * @param pub_key 公钥的内容，注意不是公钥文件的路径
 * @param pub_key_len 公钥内容长度
 * @param acctype 上传公钥之后，管理页面上获取的 accounttype
 * @param appid3rd 独立模式下为 sdkappid 字符串形式
 * @param sdkappid 创建应用之后在页面上分配的 sdkappid
 * @param identifier 用户标识符，即用户 id
 * @param err_msg 出错之后的错误信息
 * @param err_msg_buff_len 出错信息缓冲区长度
 *
 * @return 0 为成功，非 0 为失败，err_msg 中出错信息
 */
#if defined(WIN32) || defined(WIN64)
__declspec(dllexport)
#endif
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
);

/**
 * 生成 sig 的接口
 *
 * @param sdkappid 创建应用时页面上分配的 sdkappid
 * @param identifier 用户标识符，也就是用户 id，独立模式下，可以由开发者随意定义
 * @param sig 存放 sig 的缓冲区
 * @param sig_buff_len 缓冲区的长度
 * @param pri_key 私钥内容，注意不是私钥文件的路径
 * @param pri_key_len 私钥内容长度
 * @param err_msg 出错信息，如果错误，这里有出错信息
 * @param err_msg_buff_len 出息信息缓冲区长度
 * 
 * @return 0 为成功，非 0 失败，出错信息在 err_msg 中
 */
#if defined(WIN32) || defined(WIN64)
__declspec(dllexport)
#endif
int tls_gen_sig_ex(
	unsigned int sdkappid,
	const char * identifier,
	char * sig,
	unsigned int sig_buff_len,
	const char * pri_key,
	unsigned int pri_key_len,
	char * err_msg,
	unsigned int err_msg_buff_len
);

/**
 * 生成 sig 的接口
 *
 * @param sdkappid 创建应用时页面上分配的 sdkappid
 * @param identifier 用户标识符，也就是用户 id，独立模式下，可以由开发者随意定义
 * @param expire 有效期，单位秒
 * @param sig 存放 sig 的缓冲区
 * @param sig_buff_len 缓冲区的长度
 * @param pri_key 私钥内容，注意不是私钥文件的路径
 * @param pri_key_len 私钥内容长度
 * @param err_msg 出错信息，如果错误，这里有出错信息
 * @param err_msg_buff_len 出息信息缓冲区长度
 * 
 * @return 0 为成功，非 0 失败，出错信息在 err_msg 中
 */
#if defined(WIN32) || defined(WIN64)
__declspec(dllexport)
#endif
int tls_gen_sig_ex_with_expire(
	unsigned int sdkappid,
	const char * identifier,
    unsigned int expire,
	char * sig,
	unsigned int sig_buff_len,
	const char * pri_key,
	unsigned int pri_key_len,
	char * err_msg,
	unsigned int err_msg_buff_len
);

/**
 * 验证 sig 接口
 *
 * @param sig sig 的内容，以空字符结尾
 * @param pub_key 公钥的内容，注意不是公钥文件的路径
 * @param pub_key_len 公钥内容长度
 * @param sdkappid 创建应用之后在页面上分配的 sdkappid
 * @param identifier 用户标识符，即用户 id
 * @param expire_time 有效期
 * @param init_time 生成时间
 * @param err_msg 出错之后的错误信息
 * @param err_msg_buff_len 出错信息缓冲区长度
 *
 * @return 0 为成功，非 0 为失败，err_msg 中出错信息
 */
#if defined(WIN32) || defined(WIN64)
__declspec(dllexport)
#endif
int tls_vri_sig_ex(
	const char * sig,
	const char * pub_key,
	unsigned int pub_key_len,
	unsigned int sdkappid,
	const char * identifier,
    unsigned int& expire_time,
    unsigned int& init_time,
	char * err_msg,
	unsigned int err_msg_buff_len
	);

#endif

#ifdef __cplusplus
}
#endif
