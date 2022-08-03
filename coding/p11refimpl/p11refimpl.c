/*
(c) Copyright 2001, A.E.T.Europe B.V.
Project  : PKCS#11 test tools
File      : p11refimpl.c
Version   : 1.0
Date      : July 2019
Author    : AET Development Department

Description:
This test program performs the following tasks on a token:

- Searching Private key
- Sign operation
- Enumerate certificate

The program will use the first inserted token to perform the tests

On linux compile with "gcc p11refimpl.c -ldl -o p11refimpl"
*/

#include <stdio.h>

#ifdef WIN32
#include "cryptoki.h"
#include <windows.h>
#include <tchar.h>
#else 
#include "cryptoki_linux.h"
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#endif

#define PIN(pincode) (CK_CHAR_PTR)pincode,(CK_ULONG)strlen(pincode)
#define NUM_ATTRIBS(attribute_list) (sizeof(attribute_list) / sizeof(CK_ATTRIBUTE))

#ifdef WIN32
HMODULE pkcs11lib = NULL;
#else
void* pkcs11lib = NULL;
#endif

CK_FUNCTION_LIST_PTR pkcs11lib_fl = NULL_PTR;
CK_RV rv;

// This function loads the PKCS#11 module and fills the Cryptoki function array
CK_FUNCTION_LIST_PTR LoadFunctionList()
{
#ifdef WIN32
	CK_C_GetFunctionList C_GetFunctionListPtr;
#else
	void(*C_GetFunctionListPtr) (CK_FUNCTION_LIST_PTR*);
#endif
	if (NULL_PTR == pkcs11lib_fl)
	{
#ifdef WIN32
		pkcs11lib = LoadLibrary(_T("aetpkss1.dll"));
		C_GetFunctionListPtr = (CK_C_GetFunctionList)(GetProcAddress(pkcs11lib, "C_GetFunctionList"));
#else
		pkcs11lib = dlopen("libaetpkss.so", RTLD_LAZY);
		if (pkcs11lib == NULL)
			printf("Error loading PKCS11 lib : %s\n", dlerror());
		C_GetFunctionListPtr = (void(*) (CK_FUNCTION_LIST_PTR*))dlsym(pkcs11lib, "C_GetFunctionList");
#endif
		if (C_GetFunctionListPtr)
			C_GetFunctionListPtr(&pkcs11lib_fl);
	}
	return pkcs11lib_fl;
}

#define FL_CALL(func, args) \
  printf("Doing : %25s",#func " = "); \
  rv = CKR_FUNCTION_NOT_SUPPORTED; \
  LoadFunctionList(); \
  if (pkcs11lib_fl && pkcs11lib_fl->func != NULL_PTR) \
    rv = pkcs11lib_fl->func args; \
  ckrv(rv)

#define START_TEST(message) \
  printf("\n============== " message " ==============\n");

void ckrv(CK_RV inRV)
{
	switch (inRV) {
	case CKR_OK:
		printf("Ok\n");
		return;
	case CKR_PIN_INCORRECT:
		printf("PIN incorrect\n");
		break;
	case CKR_PIN_INVALID:
		printf("PIN invalid\n");
		break;
	case CKR_PIN_LEN_RANGE:
		printf("PIN either too short or too long\n");
		break;
	case CKR_PIN_EXPIRED:
		printf("PIN expired\n");
		break;
	case CKR_PIN_LOCKED:
		printf("PIN is LOCKED\n");
		break;
	case CKR_USER_PIN_NOT_INITIALIZED:
		printf("PIN not initialized\n");
		break;
	case CKR_TOKEN_NOT_PRESENT:
		printf("Token has been removed\n");
		break;
	case CKR_TOKEN_NOT_RECOGNIZED:
		printf("Token not recognized.\n");
		break;
	default:
		printf("Device Error (%lu)\n", inRV);
	}
	exit(inRV);
}

void EnumerateCertificates(CK_SESSION_HANDLE hSession)
{
	CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	CK_BYTE token_object = CK_TRUE;
	CK_ATTRIBUTE certtemplate[] = {
		{ CKA_CLASS, &certClass, sizeof(certClass) },
		{ CKA_TOKEN, &token_object, sizeof(token_object) }
	};

	CK_ULONG objectCount;
	CK_OBJECT_HANDLE hObject;
	FL_CALL(C_FindObjectsInit, (hSession, certtemplate, NUM_ATTRIBS(certtemplate)));

	while (1)
	{
		FL_CALL(C_FindObjects, (hSession, &hObject, 1, &objectCount));
		if (objectCount == 0)
		{
			break;
		}

		//certificate label
		char pszLabelBuf[40960] = { 0 };
		CK_ATTRIBUTE labelTemplate[] =
		{
			{ CKA_LABEL, pszLabelBuf, 40960 },
		};

		FL_CALL(C_GetAttributeValue, (hSession, hObject, labelTemplate, NUM_ATTRIBS(labelTemplate)));
		if (labelTemplate[0].ulValueLen > 0)
		{
			printf("Found certificate: %.*s \n\n", (int)labelTemplate[0].ulValueLen, pszLabelBuf);
		}
	}
	FL_CALL(C_FindObjectsFinal, (hSession));
}

CK_OBJECT_HANDLE FindKeyPair(CK_SESSION_HANDLE hSession)
{
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_OBJECT_CLASS privclass = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE PrivateKeyTemplate[] = {
		{ CKA_CLASS,&privclass,sizeof(privclass) },
		{ CKA_KEY_TYPE,&keyType,sizeof(keyType) }
	};
	CK_ULONG ulPrivateKeyAttributeCount = NUM_ATTRIBS(PrivateKeyTemplate);

	CK_OBJECT_HANDLE prk = 0;
	CK_ULONG ObjectCount = 0;
	FL_CALL(C_FindObjectsInit, (hSession, PrivateKeyTemplate, ulPrivateKeyAttributeCount));
	FL_CALL(C_FindObjects, (hSession, &prk, 1, &ObjectCount));
	FL_CALL(C_FindObjectsFinal, (hSession));
	if (ObjectCount == 0)
	{
		printf("Private Key not found\n");
		exit(-1);
	}
	return prk;
}

void Sign(CK_SESSION_HANDLE hSession)
{
	CK_OBJECT_HANDLE prk = FindKeyPair(hSession);

	CK_MECHANISM mechanism = { CKM_RSA_PKCS,0,0 };
	CK_ULONG dataLen = 36;
	CK_BYTE signedData[256];
	CK_ULONG signatureLen = 256;
	CK_BYTE data[] = "KJLKJLKJASFLKJASFJL AFASghrttyuihjw";

	FL_CALL(C_SignInit, (hSession, &mechanism, prk));
	FL_CALL(C_Sign, (hSession, data, dataLen, signedData, &signatureLen));

	//print the signedData
	printf("Signature: \n");
	for (CK_ULONG n = 0; n<signatureLen; n++)
	{
		printf("%02x", signedData[n]);
	}
	printf("\n");
}


int main(int argc, char* argv[])
{
	if (argc == 1)
	{
		printf("p11refimpl [pincode]\n");
		printf("example:\n");
		printf("   p11refimpl 1234\n");
		exit(-1);
	}
	char *pin = argv[1];

	CK_SESSION_HANDLE hSession;
	CK_C_INITIALIZE_ARGS initArgs = {
		NULL_PTR,
		NULL_PTR,
		NULL_PTR,
		NULL_PTR,
		CKF_OS_LOCKING_OK,
		NULL_PTR
	};

	START_TEST("Start testing...");
	FL_CALL(C_Initialize, (&initArgs));

	CK_SLOT_ID slotlist[1];
	CK_ULONG slotcount = 1;

	START_TEST("Find the first token");
	FL_CALL(C_GetSlotList, (CK_TRUE, slotlist, &slotcount));
	if (slotcount == 0)
	{
		printf("Please insert a token and rerun test \n");
		exit(CKR_FUNCTION_FAILED);
	}

	FL_CALL(C_OpenSession, (slotlist[0], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession));

	START_TEST("Enumerate the certificates");
	EnumerateCertificates(hSession);

	START_TEST("Test signing...");
	FL_CALL(C_Login, (hSession, CKU_USER, PIN(pin)));
	Sign(hSession);
	FL_CALL(C_Logout, (hSession));

	START_TEST("Close the session");
	FL_CALL(C_CloseSession, (hSession));

	START_TEST("Finalizing...");
	FL_CALL(C_Finalize, (NULL_PTR));

	if (pkcs11lib != NULL)
	{
#ifdef WIN32
		FreeLibrary(pkcs11lib);
#else
		dlclose(pkcs11lib);
#endif
	}

	return 0;
}
