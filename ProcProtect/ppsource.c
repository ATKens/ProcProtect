#include <ntifs.h>

#define PROTECT_NAME "Calculator.exe"

ULONG_PTR g_save_pid = 0;


PUCHAR PsGetProcessImageFileName(__in PEPROCESS Process);


PVOID pRegistrationHandle;
//进程管理器详细界面结束代码
#define PROCESS_TERMINATE_0       0x1001
//taskkill指令结束代码
#define PROCESS_TERMINATE_1       0x0001 
//taskkill指令加/f参数强杀进程结束码
#define PROCESS_KILL_F			  0x1401
//进程管理器结束代码
#define PROCESS_TERMINATE_2       0x1041
// _LDR_DATA_TABLE_ENTRY ,注意32位与64位的对齐大小
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
	ShutdownNoReboot,         //关机不重启
	ShutdownReboot,             //关机并重启
	ShutdownPowerOff          //关机并关闭电源
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
	// 遍历进程

		NTSTATUS status = STATUS_SUCCESS;
		ULONG i = 0;
		PEPROCESS pEProcess = NULL;
		PCHAR pszProcessName = NULL;
		// 开始遍历
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
		
	

		//重启
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

	st = KeWaitForSingleObject(objtowait, Executive, KernelMode, FALSE, NULL); //NULL表示无限期等待.
	return;
	
	
}



VOID DriverUnload(PDRIVER_OBJECT pDriver)
{

	KdPrint(("驱动正在被关闭\n"));
	// 卸载驱动

	
	if (NULL != pRegistrationHandle)
	{
		KdPrint(("卸载回调成功\n"));
		ObUnRegisterCallbacks(pRegistrationHandle);
		pRegistrationHandle = NULL;
	}

	//重启
	NtShutdownSystem(ShutdownReboot);
}

OB_PREOP_CALLBACK_STATUS PreProcessHandle(
	PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
	PEPROCESS pEProcess = NULL;
	ULONG_PTR lPid = 0;
	// 判断对象类型 
	
	/*
	__try
	{
		ProbeForRead(PsProcessType,sizeof(ULONG_PTR),4);
		//ProbeForWrite(pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess,sizeof(ULONG_PTR),4);
	}
	__except (1)
	{

		DbgPrint("PsProcessType无法访问\n");
		return OB_PREOP_SUCCESS;
	}
	*/

	if (*PsProcessType != pOperationInformation->ObjectType)
	{
		return OB_PREOP_SUCCESS;
	}

	//获取该进程结构对象的名称
	pEProcess = (PEPROCESS)pOperationInformation->Object;
	PUCHAR pProcessName = PsGetProcessImageFileName(pEProcess);

	


	// 判断是否为保护进程，不是则放行
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
			else//伪造检测
			{
				lPid = *((PULONG_PTR)((ULONG_PTR)(pEProcess)+0x440));
				DbgPrint("lPid:%llu\n", g_save_pid);

				if (lPid != g_save_pid)
				{
					NtShutdownSystem(ShutdownReboot);
				}

			}

	}


	



	// 判断操作类型,如果该句柄是终止操作，则拒绝该操作
	switch (pOperationInformation->Operation)
	{
	case OB_OPERATION_HANDLE_DUPLICATE:
		break;

	case OB_OPERATION_HANDLE_CREATE:
	{

		//如果要结束进程,进程管理器结束进程发送0x1001，taskkill指令结束进程发送0x0001，taskkil加/f参数结束进程发送0x1401
		int code = pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
		if ((code == PROCESS_TERMINATE_0) || (code == PROCESS_TERMINATE_1) || (code == PROCESS_KILL_F))
		{
			//给进程赋予新权限
			pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
			DbgPrint("重启1\n");
		}
		if (code == PROCESS_TERMINATE_2)
		{
			pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = STANDARD_RIGHTS_ALL;
			DbgPrint("重启2\n");
		}
			



		break;
	}
	}
	return OB_PREOP_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING reg_path)
{
	DbgPrint("驱动正在被启动\n");

	OB_OPERATION_REGISTRATION oor;
	OB_CALLBACK_REGISTRATION ocr;
	PLDR_DATA pld;//指向_LDR_DATA_TABLE_ENTRY结构体的指针

	//初始化
	pRegistrationHandle = 0;
	RtlZeroMemory(&oor, sizeof(OB_OPERATION_REGISTRATION));
	RtlZeroMemory(&ocr, sizeof(OB_CALLBACK_REGISTRATION));


	//初始化 OB_OPERATION_REGISTRATION 

	//设置监听的对象类型
	oor.ObjectType = PsProcessType;
	//设置监听的操作类型
	oor.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	//设置操作发生前执行的回调
	oor.PreOperation = PreProcessHandle;
	//设置操作发生前执行的回调
	//oor.PostOperation = ?

	//初始化 OB_CALLBACK_REGISTRATION 

	// 设置版本号，必须为OB_FLT_REGISTRATION_VERSION
	ocr.Version = OB_FLT_REGISTRATION_VERSION;
	//设置自定义参数，可以为NULL
	ocr.RegistrationContext = NULL;
	// 设置回调函数个数
	ocr.OperationRegistrationCount = 1;
	//设置回调函数信息结构体,如果个数有多个,需要定义为数组.
	ocr.OperationRegistration = &oor;
	RtlInitUnicodeString(&ocr.Altitude, L"321000"); // 设置加载顺序


#if DBG
	// 绕过MmVerifyCallbackFunction。
	pld = (PLDR_DATA)pDriver->DriverSection;
	pld->Flags |= 0x20;
#endif

	if (NT_SUCCESS(ObRegisterCallbacks(&ocr, &pRegistrationHandle)))
	{
		KdPrint(("ObRegisterCallbacks注册成功"));
	}
	else
	{
		KdPrint(("ObRegisterCallbacks失败"));
	}


	// 指定卸载函数
	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}
