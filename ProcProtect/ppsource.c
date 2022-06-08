#include <ntifs.h>

#define PROTECT_NAME "Calculator.exe"

ULONG_PTR g_save_pid = 0;


PUCHAR PsGetProcessImageFileName(__in PEPROCESS Process);


PVOID pRegistrationHandle;
//���̹�������ϸ�����������
#define PROCESS_TERMINATE_0       0x1001
//taskkillָ���������
#define PROCESS_TERMINATE_1       0x0001 
//taskkillָ���/f����ǿɱ���̽�����
#define PROCESS_KILL_F			  0x1401
//���̹�������������
#define PROCESS_TERMINATE_2       0x1041
// _LDR_DATA_TABLE_ENTRY ,ע��32λ��64λ�Ķ����С
#ifdef _WIN64
typedef struct _LDR_DATA
{
	LIST_ENTRY listEntry;
	ULONG64 __Undefined1;
	ULONG64 __Undefined2;
	ULONG64 __Undefined3;
	ULONG64 NonPagedDebugInfo;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING path;
	UNICODE_STRING name;
	ULONG   Flags;
}LDR_DATA, * PLDR_DATA;
#else
typedef struct _LDR_DATA
{
	LIST_ENTRY listEntry;
	ULONG unknown1;
	ULONG unknown2;
	ULONG unknown3;
	ULONG unknown4;
	ULONG unknown5;
	ULONG unknown6;
	ULONG unknown7;
	UNICODE_STRING path;
	UNICODE_STRING name;
	ULONG   Flags;
}LDR_DATA, * PLDR_DATA;
#endif


typedef   enum   _SHUTDOWN_ACTION {
	ShutdownNoReboot,         //�ػ�������
	ShutdownReboot,             //�ػ�������
	ShutdownPowerOff          //�ػ����رյ�Դ
}SHUTDOWN_ACTION;


NTSTATUS NTAPI NtShutdownSystem(IN SHUTDOWN_ACTION Action);

#define Delay_One_MicroSecond (-10)
#define Delay_One_MilliSecond (Delay_One_MicroSecond * 1000)
void MySleep(LONG msec)
{
	LARGE_INTEGER li;
	li.QuadPart = Delay_One_MilliSecond;
	li.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &li);
}

VOID IsFun()
{
	// ��������

		NTSTATUS status = STATUS_SUCCESS;
		ULONG i = 0;
		PEPROCESS pEProcess = NULL;
		PCHAR pszProcessName = NULL;
		// ��ʼ����
		for (i = 4; i < 0x10000; i = i + 4)
		{
			status = PsLookupProcessByProcessId((HANDLE)i, &pEProcess);
			if (NT_SUCCESS(status))
			{
				pszProcessName = PsGetProcessImageFileName(pEProcess);
				if (0 == _stricmp(pszProcessName, PROTECT_NAME))
				{
					i = 4;
				}

				ObDereferenceObject(pEProcess);
			}
			MySleep(50);
		}
		
	

		//����
		NtShutdownSystem(ShutdownReboot);

}


VOID IsProcessActive()
{
	


	HANDLE hThread;
	PVOID objtowait = 0;
	NTSTATUS dwStatus =
		PsCreateSystemThread(
			&hThread,
			0,
			NULL,
			(HANDLE)0,
			NULL,
			IsFun,
			NULL
		);
	NTSTATUS st;
	if ((KeGetCurrentIrql()) != PASSIVE_LEVEL)
	{
		st = KfRaiseIrql(PASSIVE_LEVEL);

	}
	if ((KeGetCurrentIrql()) != PASSIVE_LEVEL)
	{

		return;
	}

	ObReferenceObjectByHandle(
		hThread,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&objtowait,
		NULL
	);

	st = KeWaitForSingleObject(objtowait, Executive, KernelMode, FALSE, NULL); //NULL��ʾ�����ڵȴ�.
	return;
	
	
}



VOID DriverUnload(PDRIVER_OBJECT pDriver)
{

	KdPrint(("�������ڱ��ر�\n"));
	// ж������

	
	if (NULL != pRegistrationHandle)
	{
		KdPrint(("ж�ػص��ɹ�\n"));
		ObUnRegisterCallbacks(pRegistrationHandle);
		pRegistrationHandle = NULL;
	}

	//����
	NtShutdownSystem(ShutdownReboot);
}

OB_PREOP_CALLBACK_STATUS PreProcessHandle(
	PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
	PEPROCESS pEProcess = NULL;
	ULONG_PTR lPid = 0;
	// �ж϶������� 
	
	/*
	__try
	{
		ProbeForRead(PsProcessType,sizeof(ULONG_PTR),4);
		//ProbeForWrite(pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess,sizeof(ULONG_PTR),4);
	}
	__except (1)
	{

		DbgPrint("PsProcessType�޷�����\n");
		return OB_PREOP_SUCCESS;
	}
	*/

	if (*PsProcessType != pOperationInformation->ObjectType)
	{
		return OB_PREOP_SUCCESS;
	}

	//��ȡ�ý��̽ṹ���������
	pEProcess = (PEPROCESS)pOperationInformation->Object;
	PUCHAR pProcessName = PsGetProcessImageFileName(pEProcess);

	


	// �ж��Ƿ�Ϊ�������̣����������
	if (NULL != pProcessName)
	{
		if (0 != _stricmp(pProcessName, PROTECT_NAME))
		{
			
			return OB_PREOP_SUCCESS;
		}
		
			if (g_save_pid == 0)
			{ 
				g_save_pid = *((PULONG_PTR)((ULONG_PTR)(pEProcess)+0x440));
				DbgPrint("g_save_pid:%llu\n", g_save_pid);
			}
			else//α����
			{
				lPid = *((PULONG_PTR)((ULONG_PTR)(pEProcess)+0x440));
				DbgPrint("lPid:%llu\n", g_save_pid);

				if (lPid != g_save_pid)
				{
					NtShutdownSystem(ShutdownReboot);
				}

			}

	}


	



	// �жϲ�������,����þ������ֹ��������ܾ��ò���
	switch (pOperationInformation->Operation)
	{
	case OB_OPERATION_HANDLE_DUPLICATE:
		break;

	case OB_OPERATION_HANDLE_CREATE:
	{

		//���Ҫ��������,���̹������������̷���0x1001��taskkillָ��������̷���0x0001��taskkil��/f�����������̷���0x1401
		int code = pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
		if ((code == PROCESS_TERMINATE_0) || (code == PROCESS_TERMINATE_1) || (code == PROCESS_KILL_F))
		{
			//�����̸�����Ȩ��
			pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
			DbgPrint("����1\n");
		}
		if (code == PROCESS_TERMINATE_2)
		{
			pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = STANDARD_RIGHTS_ALL;
			DbgPrint("����2\n");
		}
			



		break;
	}
	}
	return OB_PREOP_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING reg_path)
{
	DbgPrint("�������ڱ�����\n");

	OB_OPERATION_REGISTRATION oor;
	OB_CALLBACK_REGISTRATION ocr;
	PLDR_DATA pld;//ָ��_LDR_DATA_TABLE_ENTRY�ṹ���ָ��

	//��ʼ��
	pRegistrationHandle = 0;
	RtlZeroMemory(&oor, sizeof(OB_OPERATION_REGISTRATION));
	RtlZeroMemory(&ocr, sizeof(OB_CALLBACK_REGISTRATION));


	//��ʼ�� OB_OPERATION_REGISTRATION 

	//���ü����Ķ�������
	oor.ObjectType = PsProcessType;
	//���ü����Ĳ�������
	oor.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	//���ò�������ǰִ�еĻص�
	oor.PreOperation = PreProcessHandle;
	//���ò�������ǰִ�еĻص�
	//oor.PostOperation = ?

	//��ʼ�� OB_CALLBACK_REGISTRATION 

	// ���ð汾�ţ�����ΪOB_FLT_REGISTRATION_VERSION
	ocr.Version = OB_FLT_REGISTRATION_VERSION;
	//�����Զ������������ΪNULL
	ocr.RegistrationContext = NULL;
	// ���ûص���������
	ocr.OperationRegistrationCount = 1;
	//���ûص�������Ϣ�ṹ��,��������ж��,��Ҫ����Ϊ����.
	ocr.OperationRegistration = &oor;
	RtlInitUnicodeString(&ocr.Altitude, L"321000"); // ���ü���˳��


#if DBG
	// �ƹ�MmVerifyCallbackFunction��
	pld = (PLDR_DATA)pDriver->DriverSection;
	pld->Flags |= 0x20;
#endif

	if (NT_SUCCESS(ObRegisterCallbacks(&ocr, &pRegistrationHandle)))
	{
		KdPrint(("ObRegisterCallbacksע��ɹ�"));
	}
	else
	{
		KdPrint(("ObRegisterCallbacksʧ��"));
	}


	// ָ��ж�غ���
	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}
