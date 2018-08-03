#include <gtest/gtest.h>

#include "tls_signature.cpp"

#define PRIVATEKEY                                                       \
    "-----BEGIN EC PARAMETERS-----\n"                                    \
    "BgUrgQQACg==\n"                                                     \
    "-----END EC PARAMETERS-----\n"                                      \
    "-----BEGIN EC PRIVATE KEY-----\n"                                   \
    "MHQCAQEEIFBooCg0a6sUn/T3zJ4LSu+jbgT03CAwkAmXmvOQ1YZboAcGBSuBBAAK\n" \
    "oUQDQgAEtqF9a4XZGHQ/npNSeTcGITcBR7lW7qz1x0M1QFxkhLM4GiBa2kv7GzLo\n" \
    "O2/YqIuXRWV5Xm9EdnrSGd3T7sHFcg==\n"                                 \
    "-----END EC PRIVATE KEY-----"

#define PUBLICKEY                                                        \
    "-----BEGIN PUBLIC KEY-----\n"                                       \
    "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEtqF9a4XZGHQ/npNSeTcGITcBR7lW7qz1\n" \
    "x0M1QFxkhLM4GiBa2kv7GzLoO2/YqIuXRWV5Xm9EdnrSGd3T7sHFcg==\n"         \
    "-----END PUBLIC KEY-----"

TEST(usersig_genrate_and_verify, 1)
{
    int ret = 0;
    std::string errmsg;
    std::string usersig;
    ret = tls_gen_signature_ex(60, "123", 1234, "12345", 6, usersig, PRIVATEKEY,
                               strlen(PRIVATEKEY), errmsg);
    ASSERT_EQ(0, ret);

    SigInfo siginfo;
    siginfo.strAccountType = "6";
    siginfo.strAppid3Rd = "123";
    siginfo.strAppid = "1234";
    siginfo.strIdentify = "12345";
    uint32_t expire;
    uint32_t init;
    ret = tls_check_signature_ex(usersig, PUBLICKEY, strlen(PUBLICKEY), siginfo,
                                 expire, init, errmsg);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(60, expire);

    //acctype appid3rd不校验
    siginfo.strAccountType = "5";
    siginfo.strAppid3Rd = "12";
    ret = tls_check_signature_ex(usersig, PUBLICKEY, strlen(PUBLICKEY), siginfo,
                                 expire, init, errmsg);
    ASSERT_EQ(0, ret);

    siginfo.strIdentify = "1";
    ret = tls_check_signature_ex(usersig, PUBLICKEY, strlen(PUBLICKEY), siginfo,
                                 expire, init, errmsg);
    ASSERT_EQ(CHECK_ERR13, ret);

    siginfo.strIdentify = "12345";
    siginfo.strAppid = "12345";
    ret = tls_check_signature_ex(usersig, PUBLICKEY, strlen(PUBLICKEY), siginfo,
                                 expire, init, errmsg);
    ASSERT_EQ(CHECK_ERR14, ret);

    ret = tls_check_signature_ex2(usersig, PUBLICKEY, 1234, "12345", expire, init, errmsg);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(60, expire);

    ret = tls_check_signature_ex2(usersig, PUBLICKEY, 123, "12345", expire, init, errmsg);
    ASSERT_EQ(CHECK_ERR14, ret);

    ret = tls_check_signature_ex2(usersig, PUBLICKEY, 1234, "2345", expire, init, errmsg);
    ASSERT_EQ(CHECK_ERR13, ret);

    ret = tls_check_signature_ex2(usersig, PUBLICKEY, 1234, "123456", expire, init, errmsg);
    ASSERT_EQ(CHECK_ERR13, ret);

    usersig = "eJxN0E9vgjAUAPA7n6LhumVrC7ixxAOKA4OLM*K2W9NIdS8IQqlSWfbd59Bsfcf3e--yviyEkJ3Olnd8vd4fSsXUqRI2ekL2wL79x6qCjHHFHJn1SKhjsNAVSMH4Rgl56cWGQiZKBRu42rnV9Qxuspz18--URNj26ZfJYjyNOD4UcuE*y9Eu1asd0a1Q969JNK-jMP4I4ebkbsMw149BAEG7jGs-J8kn6VLqRNPG180xGby-ibbl44IC7UYR1JNuFgyHxkoFxeUBxKPkgWDim584CtnAvuwLKCbe*V78G7b1bf0AYUhaRQ__";
    ret = tls_check_signature_ex2(usersig, PUBLICKEY, 1234, "12345", expire, init, errmsg);
    ASSERT_EQ(CHECK_ERR9, ret);
}

TEST(userbuf_genrate_and_verify, 1)
{
    int ret = 0;
    std::string errmsg;
    std::string usersig;
    ret = tls_gen_userbuf_ticket(1234, "12345", 60, PRIVATEKEY, "abc", usersig,
                                 errmsg);
    ASSERT_EQ(0, ret);

    uint32_t expire;
    uint32_t init;
    std::string userbuf;
    ret = tls_check_userbuf_ticket(usersig, PUBLICKEY, 1234, "12345",
                                 expire, init, userbuf, errmsg);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(60, expire);
    ASSERT_EQ("abc", userbuf);

    ret = tls_check_userbuf_ticket(usersig, PUBLICKEY, 1234, "1345",
                                 expire, init, userbuf, errmsg);
    ASSERT_EQ(CHECK_ERR13, ret);

    ret = tls_check_userbuf_ticket(usersig, PUBLICKEY, 123, "12345",
                                 expire, init, userbuf, errmsg);
    ASSERT_EQ(CHECK_ERR14, ret);
}

TEST(old_sig, 1){
    std::string errmsg;
    std::string sig;
    rapidjson::Document json;
    json.SetObject();
    json.AddMember("TLS.sdk_appid", "1", json.GetAllocator());
    json.AddMember("TLS.identifier", "2", json.GetAllocator());
    json.AddMember("TLS.expire_after", "60", json.GetAllocator());
    json.AddMember("TLS.account_type", "0", json.GetAllocator());
    json.AddMember("TLS.appid_at_3rd", "0", json.GetAllocator());
    int ret = tls_gen_signature(tls_signature_inner::Dump(&json), sig, PRIVATEKEY, strlen(PRIVATEKEY), errmsg);
    ASSERT_EQ(0, ret);

    SigInfo siginfo;
    siginfo.strAccountType = "0";
    siginfo.strAppid3Rd = "0";
    siginfo.strAppid = "1";
    siginfo.strIdentify = "2";
    uint32_t expire;
    uint32_t init;
    ret = tls_check_signature_ex(sig, PUBLICKEY, strlen(PUBLICKEY), siginfo, expire, init, errmsg);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(60, expire);
}

TEST(base64, 1){
    std::string code;
    std::string raw;

    ASSERT_EQ(0, base64_encode("123", 3, code));
    ASSERT_EQ("MTIz", code);
    ASSERT_EQ(0, base64_decode(code.data(), code.size(), raw));
    ASSERT_EQ("123", raw);

    ASSERT_EQ(0, base64_encode("\0\0\0\0\0\0", 6, code));
    ASSERT_EQ(0, base64_decode(code.data(), code.size(), raw));
    ASSERT_EQ(std::string("\0\0\0\0\0\0", 6), raw);

    ASSERT_EQ(0, base64_encode("\0\0\0\0\0", 5, code));
    ASSERT_EQ(0, base64_decode(code.data(), code.size(), raw));
    ASSERT_EQ(std::string("\0\0\0\0\0", 5), raw);

    ASSERT_EQ(0, base64_encode("\0\0\0\0", 4, code));
    ASSERT_EQ(0, base64_decode(code.data(), code.size(), raw));
    ASSERT_EQ(std::string("\0\0\0\0", 4), raw);
}

TEST(base64, 2){
    std::string code;
    std::string raw;

    ASSERT_EQ(0, base64_encode("1", 1, code));
    ASSERT_EQ("MQ==", code);
    ASSERT_EQ(0, base64_decode(code.data(), code.size(), raw));
    ASSERT_EQ("1", raw);
}

TEST(base64, decode_crlf)
{
    std::string code;
    std::string raw;

    code = "MTIz\r\nNDU2\r\nNzg5";
    ASSERT_EQ(0, base64_decode(code.data(), code.size(), raw));
    ASSERT_EQ("123456789", raw);
}

TEST(base64url, 1){
    std::string code;
    std::string raw;

    ASSERT_EQ(0, base64_encode_url("123", 3, code));
    ASSERT_EQ("MTIz", code);
    ASSERT_EQ(0, base64_decode_url(code.data(), code.size(), raw));
    ASSERT_EQ("123", raw);
}

TEST(base64url, 2){
    std::string code;
    std::string raw;

    ASSERT_EQ(0, base64_encode_url("1", 1, code));
    ASSERT_EQ("MQ__", code);
    ASSERT_EQ(0, base64_decode_url(code.data(), code.size(), raw));
    ASSERT_EQ("1", raw);
}

TEST(zlib, 1){
    std::string code;
    std::string raw;

    ASSERT_EQ(0, compress("1", 1, code));
    ASSERT_EQ(0, uncompress(code.data(), code.size(), raw));
    ASSERT_EQ("1", raw);
}

TEST(userbuf_cross, 1){
    int ret = 0;
    std::string errmsg;
    std::string usersig;
    ret = tls_gen_userbuf_ticket(1234, "12345", 60, PRIVATEKEY, "abc", usersig,
                                 errmsg);
    ASSERT_EQ(0, ret);

    uint32_t expire;
    uint32_t init;
    std::string userbuf;
    ret = tls_check_signature_ex2(usersig, PUBLICKEY, 1234, "12345", expire, init, errmsg);
    ASSERT_NE(0, ret);
}

TEST(without_appid3rd, 1) {
    std::string errmsg;
    std::string sig = "eJxNz11vgjAYBeB7fkXTW41rKwL1bkMMGnGyidu8IaxUfdehFWpkMfvv8ysL5-Y5yck5WQghPJ*8djIhdoetSc2Plhj1EabUwe1-lrWGUqbZysjyyqzHGSGkUYFcbg2s4F6gZ6UNrnKVZlpDflObXMJYc6SC9RWj4MMfxf57lz0xb8ztcd2aKgrTJYdSh8lsU8dmcnQTFaqdGC48dRxtHp8DL5qLw-fnW*Q8BCJosXj-FfpLx7eLRf2iOUnWVTEgXuI2Jg0U97s9do7LXY6tX*sPGj5LXg__";
    std::string pubkey = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAED5Ffi4qIe4XUZ5zDGR9pC0Z6UL/gCHf0\nvgoLVestQxqOGJB5mcbaKULeriaevZoq0Sx8gGtfDlSf4fXwzPtGvg==\n-----END PUBLIC KEY-----\n";

    SigInfo siginfo;
    siginfo.strAccountType = "0";
    siginfo.strAppid3Rd = "0";
    siginfo.strAppid = "1400000226";
    siginfo.strIdentify = "10001";
    uint32_t expire;
    uint32_t init;
    int ret = tls_check_signature_ex(sig, pubkey.data(), pubkey.size(), siginfo, expire, init, errmsg);
    ASSERT_EQ(9, ret);
}

TEST(sig_has_crlf, 1){
    std::string errmsg;
    std::string sig = "eJxNjV1PgzAUhv8LtxotBVIw8QImLihIpJKAWUI6KKQulK6UMWf87wIZiefuvB-P*6N9hPiurw4FEYJV2oOmmwAAZDsO0m4Xk54Fk7QgtaJy9i3LglPk6i61gqjCkHN7lRVr6RKGBjSBjVYYqyhXrGYLilQt4yunLLuBq0J9C-qP07Nm*iI-3QRbj7jHEbPYG17D9Dn4wqpuzk8JdqC4uUSN7xGujJcQy8hlvntvh5skE43aB3lWDmGXv53QMaM7ueNIHMwkRvuR4HRsP9*3cf4469fRE5U96-g0DIFu6dAA82m-f-HNW5Q_";
 std::string pubkey = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBH5u4BnS8+O4Ka510XU8SKKzDxUQ\nbrPwRg9b+YeeP/iPZn3D9eeNs22phtlj9w/5N3Sy73g9td2Y4MCONt3MwA==\n-----END PUBLIC KEY-----\n";

    SigInfo siginfo;
    siginfo.strAccountType = "0";
    siginfo.strAppid3Rd = "0";
    siginfo.strAppid = "1400078997";
    siginfo.strIdentify = "admin";
    uint32_t expire;
    uint32_t init;
    int ret = tls_check_signature_ex(sig, pubkey.data(), pubkey.size(), siginfo, expire, init, errmsg);
    ASSERT_EQ(0, ret);
}
