#include <stdlib.h>
#include <iostream>
#include <string>
#include <fstream>
#include "tls_signature.h"

using namespace std;

void usage(const char* cmd)
{
	cout << "VERSION: " << API_VERSION << endl;
	cout << "Usage:" << endl;
	cout << cmd << " privateKey sdkappid identifier" << endl;
}

int main(int argc, char **argv)
{
	if(argc != 4)
	{
		usage(argv[0]);
		return -1;
	}

	FILE *fpPrikey = fopen(argv[1], "r");
	if(fpPrikey == NULL)
	{
		cout << "open prikey file failed" << endl;
		return -1;
	}
	char pri_key_buf[1024] = {};
	size_t read_cnt = fread(pri_key_buf,1,sizeof(pri_key_buf),fpPrikey);
	
	int sdkappid = atoi(argv[2]);
	string identifier(argv[3]);

	string sig;
	string err_msg;
	string pri_key(pri_key_buf, read_cnt);

	int iRet = tls_gen_signature_ex2(sdkappid, identifier, sig, pri_key, err_msg);
	if(iRet != 0)
	{
		cout << "gen signature failed" << endl;
		cout << "error msg: " << err_msg << " return " << iRet << endl;

		fclose(fpPrikey);
		return -1;
	}

	cout << sig << endl;

	fclose(fpPrikey);
	return 0;
}
