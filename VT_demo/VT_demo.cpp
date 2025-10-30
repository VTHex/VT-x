#include <ntifs.h>
#include <intrin.h>
#include "VT_demo.h"

#define _VT_DEBUG
#define ENABLE_EPT

/* Debug */
// {
#ifndef _VT_DEBUG
#define VMERR_RET(x, s) if((x) != 0) return FALSE;
#else
#define VMERR_RET(x, s) if((x) != 0) { DbgPrint("%s Failure\n", s); return FALSE; }
#endif 

#ifndef _VT_DEBUG
#define ShowGuestState(x) 
#else
void ShowGuestState(ULONG_PTR* Registers)
{
	ULONG_PTR Rsp = 0, Rip = 0;
	ULONG_PTR Cr0, Cr3, Cr4;
	ULONG_PTR Cs, Ss, Ds, Es, Fs, Gs, Tr, Ldtr;
	ULONG_PTR GsBase, DebugCtl, Dr7, RFlags;
	ULONG_PTR IdtBase, GdtBase, IdtLimit, GdtLimit;

	__vmx_vmread(GUEST_RSP, &Rsp);
	__vmx_vmread(GUEST_RIP, &Rip);
	__vmx_vmread(GUEST_CR0, &Cr0);
	__vmx_vmread(GUEST_CR3, &Cr3);
	__vmx_vmread(GUEST_CR4, &Cr4);
	__vmx_vmread(GUEST_CS_SELECTOR, &Cs);
	__vmx_vmread(GUEST_SS_SELECTOR, &Ss);
	__vmx_vmread(GUEST_DS_SELECTOR, &Ds);
	__vmx_vmread(GUEST_ES_SELECTOR, &Es);
	__vmx_vmread(GUEST_FS_SELECTOR, &Fs);
	__vmx_vmread(GUEST_GS_SELECTOR, &Gs);
	__vmx_vmread(GUEST_TR_SELECTOR, &Tr);
	__vmx_vmread(GUEST_LDTR_SELECTOR, &Ldtr);
	__vmx_vmread(GUEST_GS_BASE, &GsBase);
	__vmx_vmread(GUEST_IA32_DEBUGCTL, &DebugCtl);
	__vmx_vmread(GUEST_DR7, &Dr7);
	__vmx_vmread(GUEST_RFLAGS, &RFlags);
	__vmx_vmread(GUEST_IDTR_BASE, &IdtBase);
	__vmx_vmread(GUEST_GDTR_BASE, &GdtBase);
	__vmx_vmread(GUEST_IDTR_LIMIT, &IdtLimit);
	__vmx_vmread(GUEST_GDTR_LIMIT, &GdtLimit);

	DbgPrint("------------ Guest state dump ------------\n");
	DbgPrint("RAX = %016llX RDX = %016llX RCX = %016llX RBX = %016llX\n", Registers[R_RAX], Registers[R_RDX], Registers[R_RCX], Registers[R_RBX]);
	DbgPrint("RBP = %016llX RDI = %016llX RSI = %016llX\n", Registers[R_RBP], Registers[R_RDI], Registers[R_RSI]);
	DbgPrint("R8 = %016llX R9  = %016llX R10 = %016llX R11 = %016llX\n", Registers[R_R8], Registers[R_R9], Registers[R_R10], Registers[R_R11]);
	DbgPrint("R12 = %016llX R13 = %016llX R14 = %016llX R15 = %016llX\n", Registers[R_R12], Registers[R_R13], Registers[R_R14], Registers[R_R15]);
	DbgPrint("RSP = %016llX RIP = %016llX\n", Rsp, Rip);
	DbgPrint("CR0 = %016llX CR3 = %016llX CR4 = %016llX\n", Cr0, Cr3, Cr4);
	DbgPrint("CS = %016llX, SS = %016llX, DS = %016llX\n", Cs, Ss, Ds);
	DbgPrint("ES = %016llX, FS = %016llX, GS = %016llX\n", Es, Fs, Gs);
	DbgPrint("TR = %016llX, LDTR = %016llX, DebugCTL = %016llX\n", Tr, Ldtr, DebugCtl);
	DbgPrint("DR7 = %016llX, RFlags = %016llX\n", Dr7, RFlags);
	DbgPrint("GsBase = %016llX\n", GsBase);
	DbgPrint("IdtBase = %016llX IdtLimit = %016llX\n", IdtBase, IdtLimit);
	DbgPrint("GdtBase = %016llX\n", GdtBase, GdtLimit);
	DbgPrint("------------ States dump ends ------------\n");

	return VOID();
}
#endif 
// }

#define VMWRITE_ERR_RET(e, v, s) { \
 DbgPrint("%s : %016llx\n", #e, v);\
 VMERR_RET(vmwrite(e, v), "vmwrite-" s); \
}
#define VMREAD_ERR_RET(e, v, s) VMERR_RET(vmread(e, v), "vmread-" s);

__forceinline ULONG_PTR VmxAdjustMsr(ULONG_PTR MsrValue, ULONG_PTR DesiredValue)
{
	DesiredValue &= (MsrValue >> 32);
	DesiredValue |= (MsrValue & 0xFFFFFFFF);
	return DesiredValue;
}

/* May fails with VMError, check return value */
__forceinline unsigned char vmwrite(VMCSFIELD Encoding, ULONG_PTR Value)
{
	return __vmx_vmwrite(Encoding, Value);
}

__forceinline unsigned char vmread(VMCSFIELD Encoding, ULONG_PTR* Value)
{
	return __vmx_vmread(Encoding, Value);
}

__forceinline unsigned char vmlaunch(void)
{
	return __vmx_vmlaunch();
}

__forceinline unsigned char vmresume(void)
{
	return __vmx_vmresume();
}

__forceinline unsigned char vmxon(ULONG_PTR* VmxRegion)
{
	return __vmx_on(VmxRegion);
}

__forceinline void vmxoff(void)
{
	return __vmx_off();
}

__forceinline unsigned char vmclear(ULONG_PTR* Vmcs)
{
	return __vmx_vmclear(Vmcs);
}

__forceinline unsigned char vmptrld(ULONG_PTR* Vmcs)
{
	return __vmx_vmptrld(Vmcs);
}

__forceinline void vmptrst(ULONG_PTR* Vmcs)
{
	return __vmx_vmptrst(Vmcs);
}

SimpleVT::SimpleVT()
{
	PHYSICAL_ADDRESS highest;
	highest.QuadPart = 0xFFFFFFFFFFFFFFFFL;

	/* Allocate vmx region and vmcs */
	m_VMXRegion = (ULONG_PTR*)(MmAllocateNonCachedMemory(PAGE_SIZE));
	if (m_VMXRegion) RtlSecureZeroMemory(m_VMXRegion, PAGE_SIZE);
	m_VMCS = (ULONG_PTR*)(MmAllocateNonCachedMemory(PAGE_SIZE));
	if (m_VMCS) RtlSecureZeroMemory(m_VMCS, PAGE_SIZE);
	m_MsrBitmap = (UINT8*)(MmAllocateNonCachedMemory(PAGE_SIZE));
	if (m_MsrBitmap) RtlSecureZeroMemory(m_MsrBitmap, PAGE_SIZE);
	m_VMXOn = FALSE;

	/* Initialize hypervisor states */
	m_VMXRootStack = (ULONG_PTR)MmAllocateNonCachedMemory(0x3000);
	if (m_VMXRootStack)
		this->SetVMExitHandler((ULONG_PTR)_VMExitHandler, m_VMXRootStack + 0x2000);

	return;
}

BOOLEAN SimpleVT::Install(void)
{
	BOOLEAN ret;

	/* Check and install */
	if (!CheckVTSupported()) {
		return FALSE;
	}

	if (!CheckVTEnabled()) {
		return FALSE;
	}

	ret = this->InitVMCS();

	__writeds(0x28 | 0x3);
	__writees(0x28 | 0x3);
	__writefs(0x50 | 0x3);
	return ret;
}

BOOLEAN SimpleVT::CheckVTSupported(void) {
	int ctx[4];		// EAX, EBX, ECX, EDX
	BOOLEAN result = TRUE;
	/*
	检查CPU硬件是否支持VMX指令集
	void __cpuidex(
	int cpuinfo[4], 包含在eax,ebx,ecx,edx中返回的有关cpu支持的功能的信息
	int function_id,在eax中传递的指定要检索的信息的代码
	int subfunction_id  在ecx中传递的指定要检索的信息的附加代码
	)
	*/
	/* check processor capability */
	__cpuidex(ctx, 1, 0);
	if ((ctx[2] & CPUID_1_ECX_VMX) == 0) {	// check VMX bit
		result = FALSE;
	}
	return result;
}

BOOLEAN SimpleVT::InitializeEPT(void) {
	PHYSICAL_ADDRESS highest;
	int i, j, k;
	SHV_MTRR_RANGE MtrrData[16];
	ULONG_PTR LargePageAddress, CandidateMemoryType;
	MTRR_CAPABILITIES mtrrCapabilities;
	MTRR_VARIABLE_BASE mtrrBase;
	MTRR_VARIABLE_MASK mtrrMask;
	unsigned long bit;

	this->m_Ept = NULL;

	highest.QuadPart = 0xFFFFFFFFFFFFFFFFL;

	this->m_Ept = (PVMX_EPT)MmAllocateContiguousMemory(sizeof(VMX_EPT), highest);
	if (!m_Ept)	goto bailout;
	RtlSecureZeroMemory(this->m_Ept, sizeof(VMX_EPT));

	//
	// Read the capabilities mask
	//
	mtrrCapabilities.AsUlonglong = __readmsr(MTRR_MSR_CAPABILITIES);

	//
	// Iterate over each variable MTRR
	//
	for (i = 0; i < mtrrCapabilities.u.VarCnt; i++)
	{
		//
		// Capture the value
		//
		mtrrBase.AsUlonglong = __readmsr(MTRR_MSR_VARIABLE_BASE + i * 2);
		mtrrMask.AsUlonglong = __readmsr(MTRR_MSR_VARIABLE_MASK + i * 2);

		//
		// Check if the MTRR is enabled
		//
		MtrrData[i].Type = (UINT32)mtrrBase.u.Type;
		MtrrData[i].Enabled = (UINT32)mtrrMask.u.Enabled;
		if (MtrrData[i].Enabled != FALSE)
		{
			//
			// Set the base
			//
			MtrrData[i].PhysicalAddressMin = mtrrBase.u.PhysBase * MTRR_PAGE_SIZE;

			//
			// Compute the length
			//
			_BitScanForward64(&bit, mtrrMask.u.PhysMask * MTRR_PAGE_SIZE);
			MtrrData[i].PhysicalAddressMax = MtrrData[i].PhysicalAddressMin + (1ULL << bit) - 1;
		}
	}

	/* First 512 G */
	m_Ept->Epml4[0].Read = 1;
	m_Ept->Epml4[0].Write = 1;
	m_Ept->Epml4[0].Execute = 1;
	m_Ept->Epml4[0].PageFrameNumber = (MmGetPhysicalAddress(&m_Ept->Epdpt).QuadPart) / PAGE_SIZE;

	for (i = 0; i < PDPTE_ENTRY_COUNT; i++)
	{
		//
		// Set the page frame number of the PDE table
		//
		m_Ept->Epdpt[i].Read = m_Ept->Epdpt[i].Write = m_Ept->Epdpt[i].Execute = 1;
		m_Ept->Epdpt[i].PageFrameNumber = (MmGetPhysicalAddress(&m_Ept->Epde[i][0]).QuadPart) / PAGE_SIZE;
	}

	for (i = 0; i < PDPTE_ENTRY_COUNT; i++)
	{
		//
		// Construct EPT identity map for every 2MB of RAM
		//
		for (j = 0; j < PDE_ENTRY_COUNT; j++)
		{
			m_Ept->Epde[i][j].Read = m_Ept->Epde[i][j].Write = m_Ept->Epde[i][j].Execute = m_Ept->Epde[i][j].Large = 1;
			m_Ept->Epde[i][j].PageFrameNumber = (i * 512) + j;
			LargePageAddress = m_Ept->Epde[i][j].PageFrameNumber * _2MB;
			CandidateMemoryType = MTRR_TYPE_WB;
			for (k = 0; k < sizeof(MtrrData) / sizeof(MtrrData[0]); k++)
			{
				//
				// Check if it's active
				//
				if (MtrrData[k].Enabled != FALSE)
				{
					//
					// Check if this large page falls within the boundary. If a single
					// physical page (4KB) touches it, we need to override the entire 2MB.
					//
					if (((LargePageAddress + _2MB) >= MtrrData[k].PhysicalAddressMin) &&
						(LargePageAddress <= MtrrData[k].PhysicalAddressMax))
					{
						//
						// Override candidate type with MTRR type
						//
						CandidateMemoryType = MtrrData[k].Type;
					}
				}
			}
			m_Ept->Epde[i][j].Type = CandidateMemoryType;
		}
	}

	return TRUE;
bailout:

	return FALSE;
}

BOOLEAN SimpleVT::CheckVTEnabled(void) {
	ULONG_PTR msr;
	//该寄存器用于控制CPU的硬件特征，包括VT-x的启动状态
	msr = __readmsr(IA32_FEATURE_CONTROL_CODE);
	if ((msr & FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX) == 0)	return FALSE;
	return TRUE;
}

VOID SimpleVT::SetVMExitHandler(ULONG_PTR HandlerEntryPoint, ULONG_PTR HandlerStack)
{
	this->m_HostState.rip = HandlerEntryPoint;
	this->m_HostState.rsp = ROUNDUP(HandlerStack, PAGE_SIZE);
	return VOID();
}

VOID SimpleVT::SetRootmodeCR3(ULONG_PTR Cr3)
{
	this->m_HostState.cr3 = Cr3;
	return VOID();
}

BOOLEAN SimpleVT::InitVMCS(void) {
	ULONG_PTR ReturnAddress, StackPointer;
	ULONG_PTR base, limit, rights;
	VMX_EPTP vmxEptp;

	UNREFERENCED_PARAMETER(vmxEptp);

	/* Guest states */
	StackPointer = (ULONG_PTR)(_StackPointer());
	ReturnAddress = (ULONG_PTR)(_NextInstructionPointer());

	if (m_VMXOn) {
		DbgPrint("VM Running!\n");
		return TRUE;
	}

	if (!m_VMCS || !m_VMXRegion || !m_MsrBitmap) {	/* memory allocation failure */
		return FALSE;
	}
	m_VmcsPhysAddr = MmGetPhysicalAddress(m_VMCS).QuadPart;
	m_VmxRegionPhysAddr = MmGetPhysicalAddress(m_VMXRegion).QuadPart;
	m_MsrBitmapPhysAddr = MmGetPhysicalAddress(m_MsrBitmap).QuadPart;

	DbgPrint("VMCS Virt = %016llX, Phys = %016llX\n", m_VMCS, m_VmcsPhysAddr);

	/* Check features */
	m_VmxBasic = __readmsr(IA32_VMX_BASIC_MSR_CODE);
	m_VmxFeatureControl = __readmsr(IA32_FEATURE_CONTROL_CODE);

	/* Set revision id */
	*(PULONG32)(m_VMXRegion) = (ULONG32)m_VmxBasic;
	*(PULONG32)(m_VMCS) = (ULONG32)m_VmxBasic;

	/* Enable VMX Operation */
	//__writecr4(__readcr4() | CR4_VMXE);

	/* Initialize guest state */
	// {
	m_GuestState.cs = __readcs();
	m_GuestState.ds = __readds();
	m_GuestState.ss = __readss();
	m_GuestState.es = __reades();
	m_GuestState.fs = __readfs();
	m_GuestState.gs = __readgs();
	m_GuestState.ldtr = __sldt();
	m_GuestState.tr = __str();
	m_GuestState.rip = ReturnAddress;
	m_GuestState.rflags = __readeflags();
	m_GuestState.rsp = StackPointer;
	__sgdt(&(m_GuestState.gdt));
	__sidt(&(m_GuestState.idt));
	m_GuestState.cr3 = __readcr3();
	m_GuestState.cr0 = ((__readcr0() & __readmsr(IA32_VMX_CR0_FIXED1)) | __readmsr(IA32_VMX_CR0_FIXED0));
	m_GuestState.cr4 = ((__readcr4() & __readmsr(IA32_VMX_CR4_FIXED1)) | __readmsr(IA32_VMX_CR4_FIXED0));
	m_GuestState.dr7 = __readdr(7);
	m_GuestState.msr_debugctl = __readmsr(IA32_DEBUGCTL);
	m_GuestState.msr_sysenter_cs = __readmsr(IA32_SYSENTER_CS);
	m_GuestState.msr_sysenter_eip = __readmsr(IA32_SYSENTER_EIP);
	m_GuestState.msr_sysenter_esp = __readmsr(IA32_SYSENTER_ESP);
	// }

	__writecr0(m_GuestState.cr0);
	__writecr4(m_GuestState.cr4);

	/* Initialize Host state */
	// {
	m_HostState.cr0 = __readcr0();
	//m_HostState.cr3 = __readcr3();
	m_HostState.cr4 = __readcr4();
	m_HostState.cs = __readcs() & 0xf8;
	m_HostState.ds = __readds() & 0xf8;
	m_HostState.ss = __readss() & 0xf8;
	m_HostState.es = __reades() & 0xf8;
	m_HostState.fs = __readfs() & 0xf8;
	m_HostState.gs = __readgs() & 0xf8;
	m_HostState.tr = __str();
	m_HostState.msr_sysenter_cs = __readmsr(IA32_SYSENTER_CS);
	m_HostState.msr_sysenter_eip = __readmsr(IA32_SYSENTER_EIP);
	m_HostState.msr_sysenter_esp = __readmsr(IA32_SYSENTER_ESP);
	__sgdt(&(m_HostState.gdt));
	__sidt(&(m_HostState.idt));
	// }

	/* Initialize Extended Page Table */
#ifdef ENABLE_EPT
	if (!InitializeEPT()) {
		DbgPrint("Failed init EPT\n");
		return FALSE;
	}
#endif

	/* Setup VMX */
	// {
	VMERR_RET(vmxon(&m_VmxRegionPhysAddr), "vmxon");	// vmxon
	DbgPrint("vmxon success\n");
	m_VMXOn = TRUE;

	VMERR_RET(vmclear(&m_VmcsPhysAddr), "vmclear");
	VMERR_RET(vmptrld(&m_VmcsPhysAddr), "vmptrld");
	DbgPrint("VMCS loaded\n");
	// }

	/* Setup VMCS */
	// {
	/* Guest Non-Register States */
	// Activity state
	// Interruptibility state
	// Pending debug exceptions
	VMWRITE_ERR_RET(VMCS_LINK_POINTER, 0xFFFFFFFFFFFFFFFFL, "VMCS_LINK_PTR");
	//VMWRITE_ERR_RET(VMCS_LINK_POINTER_HIGH, 0xFFFFFFFFFFFFFFFFL, "VMCS_LINK_PTR_HI");

	/* Enable EPT */
#ifdef ENABLE_EPT
	vmxEptp.AsUlonglong = 0;
	vmxEptp.PageWalkLength = 3;
	vmxEptp.Type = MTRR_TYPE_WB;
	vmxEptp.PageFrameNumber = ((MmGetPhysicalAddress(&(m_Ept->Epml4)).QuadPart)) / PAGE_SIZE;
	VMWRITE_ERR_RET(EPT_POINTER, vmxEptp.AsUlonglong, "EPT_POINTER");
	VMWRITE_ERR_RET(VIRTUAL_PROCESSOR_ID, 1, "VIRT_PROC_ID");
#endif

	/* VM Execution control fields */
	VMWRITE_ERR_RET(MSR_BITMAP, m_MsrBitmapPhysAddr, "MSR_BITMAP");
#ifdef ENABLE_EPT
	VMWRITE_ERR_RET(SECONDARY_VM_EXEC_CONTROL, VmxAdjustMsr(__readmsr(IA32_VMX_PROCBASED_CTLS2), SECONDARY_EXEC_XSAVES | SECONDARY_EXEC_ENABLE_RDTSCP | SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_ENABLE_VPID), "Proc_Based_CTLS2");
#else 
	VMWRITE_ERR_RET(SECONDARY_VM_EXEC_CONTROL, VmxAdjustMsr(__readmsr(IA32_VMX_PROCBASED_CTLS2), SECONDARY_EXEC_XSAVES | SECONDARY_EXEC_ENABLE_RDTSCP), "Proc_Based_CTLS2");
#endif
	VMWRITE_ERR_RET(PIN_BASED_VM_EXEC_CONTROL, VmxAdjustMsr(__readmsr(MSR_IA32_VMX_TRUE_PINBASED_CTLS), 0), "Pin_Based_CTLS");	// we don't need to monitor these VM exits
	VMWRITE_ERR_RET(CPU_BASED_VM_EXEC_CONTROL, VmxAdjustMsr(__readmsr(MSR_IA32_VMX_TRUE_PROCBASED_CTLS), CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_ACTIVATE_MSR_BITMAP), "Proc_Based_CTLS");	// as above
	//VMWRITE_ERR_RET(EXCEPTION_BITMAP, 0xFFFFFFFF, "EXCEPTION_BITMAP");
	// TODO : Exception bitmap (if we want do exception monitoring)
	// Most of the other functionalities are disabled in CPU_BASED_VM_EXEC_CONTROL
	//VMWRITE_ERR_RET(CR3_TARGET_COUNT, 0, "CR3_TARGET_COUNT");
	//VMWRITE_ERR_RET(CR0_GUEST_HOST_MASK, 0, "CR0_GUEST_HOST_MASK");
	//VMWRITE_ERR_RET(CR4_GUEST_HOST_MASK, 0, "CR4_GUEST_HOST_MASK");

	/* VM Exit & Entry control fields */
	VMWRITE_ERR_RET(VM_EXIT_CONTROLS, VmxAdjustMsr(__readmsr(MSR_IA32_VMX_TRUE_EXIT_CTLS), VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT), "VMEXIT_CTLS");
	VMWRITE_ERR_RET(VM_ENTRY_CONTROLS, VmxAdjustMsr(__readmsr(MSR_IA32_VMX_TRUE_ENTRY_CTLS), VM_ENTRY_IA32E_MODE), "VMENTRY_CTLS");
	//VMWRITE_ERR_RET(VM_EXIT_MSR_LOAD_COUNT, 0, "VMEXIT_MSR_LOAD_COUNT");
	//VMWRITE_ERR_RET(VM_EXIT_MSR_STORE_COUNT, 0, "VMEXIT_MSR_STORE_COUNT");
	//VMWRITE_ERR_RET(VM_ENTRY_MSR_LOAD_COUNT, 0, "VMENTRY_MSR_LOAD_COUNT");

	/* Guest Register States */
	this->GdtEntryToVmcsFormat(m_GuestState.cs, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_CS_SELECTOR, m_GuestState.cs, "Guest_CS_Selector");
	VMWRITE_ERR_RET(GUEST_CS_LIMIT, limit, "Guest_CS_Limit");
	VMWRITE_ERR_RET(GUEST_CS_AR_BYTES, rights, "Guest_CS_Rights");
	VMWRITE_ERR_RET(GUEST_CS_BASE, base, "Guest_CS_Base");
	VMWRITE_ERR_RET(HOST_CS_SELECTOR, m_HostState.cs, "Host_CS");

	this->GdtEntryToVmcsFormat(m_GuestState.ss, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_SS_SELECTOR, m_GuestState.ss, "Guest_SS_Selector");
	VMWRITE_ERR_RET(GUEST_SS_LIMIT, limit, "Guest_SS_Limit");
	VMWRITE_ERR_RET(GUEST_SS_AR_BYTES, rights, "Guest_SS_Rights");
	VMWRITE_ERR_RET(GUEST_SS_BASE, base, "Guest_SS_Base");
	VMWRITE_ERR_RET(HOST_SS_SELECTOR, m_HostState.ss, "Host_SS");

	this->GdtEntryToVmcsFormat(m_GuestState.ds, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_DS_SELECTOR, m_GuestState.ds, "Guest_DS_Selector");
	VMWRITE_ERR_RET(GUEST_DS_LIMIT, limit, "Guest_DS_Limit");
	VMWRITE_ERR_RET(GUEST_DS_AR_BYTES, rights, "Guest_DS_Rights");
	VMWRITE_ERR_RET(GUEST_DS_BASE, base, "Guest_DS_Base");
	VMWRITE_ERR_RET(HOST_DS_SELECTOR, m_HostState.ds, "Host_DS");

	this->GdtEntryToVmcsFormat(m_GuestState.es, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_ES_SELECTOR, m_GuestState.es, "Guest_ES_Selector");
	VMWRITE_ERR_RET(GUEST_ES_LIMIT, limit, "Guest_ES_Limit");
	VMWRITE_ERR_RET(GUEST_ES_AR_BYTES, rights, "Guest_ES_Rights");
	VMWRITE_ERR_RET(GUEST_ES_BASE, base, "Guest_ES_Base");
	VMWRITE_ERR_RET(HOST_ES_SELECTOR, m_HostState.es, "Host_ES");

	this->GdtEntryToVmcsFormat(m_GuestState.fs, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_FS_SELECTOR, m_GuestState.fs, "Guest_FS_Selector");
	VMWRITE_ERR_RET(GUEST_FS_LIMIT, limit, "Guest_FS_Limit");
	VMWRITE_ERR_RET(GUEST_FS_AR_BYTES, rights, "Guest_FS_Rights");
	VMWRITE_ERR_RET(GUEST_FS_BASE, base, "Guest_FS_Base");
	VMWRITE_ERR_RET(HOST_FS_BASE, base, "Host_FS_Base");
	VMWRITE_ERR_RET(HOST_FS_SELECTOR, m_HostState.fs, "Host_FS");

	this->GdtEntryToVmcsFormat(m_GuestState.gs, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_GS_SELECTOR, m_GuestState.gs, "Guest_GS_Selector");
	base = __readmsr(MSR_GS_BASE);
	VMWRITE_ERR_RET(GUEST_GS_LIMIT, limit, "Guest_GS_Limit");
	VMWRITE_ERR_RET(GUEST_GS_AR_BYTES, rights, "Guest_GS_Rights");
	VMWRITE_ERR_RET(GUEST_GS_BASE, base, "Guest_GS_Base");
	VMWRITE_ERR_RET(HOST_GS_BASE, base, "Host_GS_Base");
	VMWRITE_ERR_RET(HOST_GS_SELECTOR, m_HostState.gs, "Host_GS");

	this->GdtEntryToVmcsFormat(m_GuestState.tr, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_TR_SELECTOR, m_GuestState.tr, "Guest_TR_Selector");
	VMWRITE_ERR_RET(GUEST_TR_LIMIT, limit, "Guest_TR_Limit");
	VMWRITE_ERR_RET(GUEST_TR_AR_BYTES, rights, "Guest_TR_Rights");
	VMWRITE_ERR_RET(GUEST_TR_BASE, base, "Guest_TR_Base");
	VMWRITE_ERR_RET(HOST_TR_BASE, base, "Host_TR_Base");
	VMWRITE_ERR_RET(HOST_TR_SELECTOR, m_HostState.tr, "Host_TR");

	this->GdtEntryToVmcsFormat(m_GuestState.ldtr, &base, &limit, &rights);
	VMWRITE_ERR_RET(GUEST_LDTR_SELECTOR, m_GuestState.ldtr, "Guest_LDTR_Selector");
	VMWRITE_ERR_RET(GUEST_LDTR_LIMIT, limit, "Guest_LDTR_Limit");
	VMWRITE_ERR_RET(GUEST_LDTR_AR_BYTES, rights, "Guest_LDTR_Rights");
	VMWRITE_ERR_RET(GUEST_LDTR_BASE, base, "Guest_LDTR_Base");

	VMWRITE_ERR_RET(GUEST_GDTR_BASE, m_GuestState.gdt.ulBase, "Guest_GDTR_Base");
	VMWRITE_ERR_RET(GUEST_GDTR_LIMIT, m_GuestState.gdt.wLimit, "Guest_GDTR_Limit");
	VMWRITE_ERR_RET(HOST_GDTR_BASE, m_HostState.gdt.ulBase, "Host_GDTR_Base");

	VMWRITE_ERR_RET(GUEST_IDTR_BASE, m_GuestState.idt.ulBase, "Guest_IDTR_Base");
	VMWRITE_ERR_RET(GUEST_IDTR_LIMIT, m_GuestState.idt.wLimit, "Guest_IDTR_Limit");
	VMWRITE_ERR_RET(HOST_IDTR_BASE, m_HostState.idt.ulBase, "Host_IDTR_Base");

	VMWRITE_ERR_RET(CR0_READ_SHADOW, m_GuestState.cr0, "CR0_READ_SHADOW");
	VMWRITE_ERR_RET(HOST_CR0, m_HostState.cr0, "Host_CR0");
	VMWRITE_ERR_RET(GUEST_CR0, m_GuestState.cr0, "Guest_CR0");

	VMWRITE_ERR_RET(HOST_CR3, m_HostState.cr3, "Host_CR3");
	VMWRITE_ERR_RET(GUEST_CR3, m_GuestState.cr3, "Guest_CR3");

	VMWRITE_ERR_RET(HOST_CR4, m_HostState.cr4, "Host_CR4");
	VMWRITE_ERR_RET(GUEST_CR4, m_GuestState.cr4, "Guest_CR4");
	VMWRITE_ERR_RET(CR4_READ_SHADOW, m_GuestState.cr4, "CR4_READ_SHADOW");

	VMWRITE_ERR_RET(GUEST_IA32_DEBUGCTL, m_GuestState.msr_debugctl, "Guest_DEBUGCTL");
	VMWRITE_ERR_RET(GUEST_DR7, m_GuestState.dr7, "Guest_DR7");
	VMWRITE_ERR_RET(GUEST_RSP, m_GuestState.rsp, "Guest_RSP");
	VMWRITE_ERR_RET(GUEST_RIP, m_GuestState.rip, "Guest_RIP");
	VMWRITE_ERR_RET(GUEST_RFLAGS, m_GuestState.rflags, "Guest_RFLAGS");

	/* Host State area */
	// Processor state is loaded from here on VMEXIT
	VMWRITE_ERR_RET(HOST_RIP, m_HostState.rip, "Host_RIP");
	VMWRITE_ERR_RET(HOST_RSP, m_HostState.rsp, "Host_RSP");

	// }

	/* Now Launch the vm */
	DbgPrint("VMCS Initialized\n");
	m_VMXOn = TRUE;
	vmlaunch();

	/* if we reach here, we failed */
	DbgPrint("vmlaunch failed\n");
	m_VMXOn = FALSE;

	return FALSE;
}

VOID SimpleVT::GdtEntryToVmcsFormat(ULONG selector, ULONG_PTR* base, ULONG_PTR* limit, ULONG_PTR* rights)
{
	GDT gdtr;
	PKGDTENTRY64 gdtEntry;

	// ???
	*base = *limit = *rights = 0;

	if (selector == 0 || (selector & SELECTOR_TABLE_INDEX) != 0) {
		*rights = 0x10000;	// unusable
		return;
	}

	__sgdt(&gdtr);
	gdtEntry = (PKGDTENTRY64)(gdtr.ulBase + (selector & ~(0x3)));

	*limit = __segmentlimit(selector);
	*base = ((gdtEntry->Bytes.BaseHigh << 24) | (gdtEntry->Bytes.BaseMiddle << 16) | (gdtEntry->BaseLow)) & 0xFFFFFFFF;
	*base |= ((gdtEntry->Bits.Type & 0x10) == 0) ? ((uintptr_t)gdtEntry->BaseUpper << 32) : 0;
	*rights = (gdtEntry->Bytes.Flags1) | (gdtEntry->Bytes.Flags2 << 8);
	*rights |= (gdtEntry->Bits.Present) ? 0 : 0x10000;

	return VOID();
}

/* Basic VM Exit Handler */
// {
EXTERN_C BOOLEAN VMExitHandler(ULONG_PTR* Registers)
{
	ULONG_PTR ExitReason = 0;
	ULONG_PTR GuestRSP = 0;
	ULONG_PTR GuestRIP = 0;
	ULONG_PTR ExitInstructionLength = 0;
	ULONG_PTR GuestRFLAGS = 0;
	ULONG_PTR ExitQualification = 0;
	ULONGLONG TempResult;
	ULONG_PTR numCR, accType, opType, reg, cr3;
	ULONG_PTR GuestVirt, GuestPhys;
	ULONG_PTR IdtVector, IdtVectorErrCode, InstructionInfo;
	int CPUInfo[4];

	// TODO : Add VMExit Callbacks

	/* Read necessary fields */
	VMREAD_ERR_RET(GUEST_RIP, &GuestRIP, "GuestRIP");
	VMREAD_ERR_RET(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength, "ExitILen");
	VMREAD_ERR_RET(VM_EXIT_REASON, &ExitReason, "Read_ExitReason");
	VMREAD_ERR_RET(EXIT_QUALIFICATION, &ExitQualification, "ExitQualification");	// 27.2.1
	VMREAD_ERR_RET(GUEST_RFLAGS, &GuestRFLAGS, "Guest_RFLAGS");
	VMREAD_ERR_RET(GUEST_RSP, &GuestRSP, "Guest_RSP");
	VMREAD_ERR_RET(GUEST_CR3, &cr3, "Guest_CR3");
	VMREAD_ERR_RET(GUEST_GS_BASE, &reg, "Guest_GS_BASE");
	VMREAD_ERR_RET(GUEST_LINEAR_ADDRESS, &GuestVirt, "Guest_LINEAR");
	VMREAD_ERR_RET(GUEST_PHYSICAL_ADDRESS, &GuestPhys, "Guest_PHYS");
	VMREAD_ERR_RET(IDT_VECTORING_INFO, &IdtVector, "IdtVector");
	VMREAD_ERR_RET(IDT_VECTORING_ERROR_CODE, &IdtVectorErrCode, "IdtVector");
	VMREAD_ERR_RET(VMX_INSTRUCTION_INFO, &InstructionInfo, "VmInstrInfo");

	//DbgPrint("CR2 = %016llX\n", __readcr2());
	//DbgPrint("Exit Reason = %x\n", ExitReason);
	//DbgPrint("ExitQualification = %016llX\n", ExitQualification);
	//DbgPrint("Guest Linear = %016llX\n", GuestVirt);
	//DbgPrint("Guest Physical = %016llX\n", GuestPhys);
	//DbgPrint("IDT Vectoring Info = %016llX\n", IdtVector);
	//DbgPrint("IDT Vectoring Error code = %016llX\n", IdtVectorErrCode);
	//DbgPrint("VMExit Instruction Info = %016llX\n", InstructionInfo);

	//ShowGuestState(Registers);

	/* Default handlers */
	// These handlers handles VMX Operations, RDMSR, WRMSR, MOV CRX, INVD
	switch (ExitReason) {
	case VMX_EXIT_CPUID:
		if (Registers[R_RAX] == 0x41414141) {
			ShowGuestState(Registers);
			Registers[R_RBX] = 0xDEADBEEF;
			Registers[R_RCX] = 0x13371337;
		}
		else {
			__cpuidex(CPUInfo, Registers[R_RAX], Registers[R_RCX]);
			Registers[R_RAX] = (ULONG_PTR)CPUInfo[0];
			Registers[R_RBX] = (ULONG_PTR)CPUInfo[1];
			Registers[R_RCX] = (ULONG_PTR)CPUInfo[2];
			Registers[R_RDX] = (ULONG_PTR)CPUInfo[3];
		}
		break;
	case VMX_EXIT_VMCALL:
		/* TODO : Issue VMXOFF Logic & other vmcall logic here */
		break;
	case VMX_EXIT_VMCLEAR:	// VMX Operations are denied
	case VMX_EXIT_VMLAUNCH:
	case VMX_EXIT_VMPTRLD:
	case VMX_EXIT_VMPTRST:
	case VMX_EXIT_VMREAD:
	case VMX_EXIT_VMRESUME:
	case VMX_EXIT_VMWRITE:
	case VMX_EXIT_VMXOFF:
	case VMX_EXIT_VMXON:
		VMWRITE_ERR_RET(GUEST_RFLAGS, GuestRFLAGS | 0x1, "Guest_RFLAGS");
		break;
	case VMX_EXIT_RDMSR:	// 
		TempResult = __readmsr(Registers[R_RCX]);
		Registers[R_RAX] = LODWORD(TempResult);
		Registers[R_RDX] = HIDWORD(TempResult);
		break;
	case VMX_EXIT_WRMSR:
		TempResult = MAKEQWORD(Registers[R_RAX], Registers[R_RDX]);
		__writemsr(Registers[R_RCX], TempResult);
		break;
	case VMX_EXIT_MOV_CRX:
		numCR = ExitQualification & 0b1111;
		accType = (ExitQualification & 0b110000) >> 4;
		opType = (ExitQualification >> 6) & 1;
		reg = (ExitQualification >> 8) & 0b1111;
		/* We only handle mov cr3, reg && mov reg, cr3 */
		if (numCR == 3 && opType == 0) {
			if (accType == 1) {		// mov reg, cr3
				VMREAD_ERR_RET(GUEST_CR3, &cr3, "Guest_CR3");
				Registers[reg] = cr3;
			}
			else if (accType == 0) {	// mov cr3, reg
				cr3 = Registers[reg];
				VMWRITE_ERR_RET(GUEST_CR3, cr3, "Guest_CR3");
			}
		}
		break;
	case VMX_EXIT_XSETBV:
		_xsetbv(Registers[R_RCX], MAKEQWORD(Registers[R_RAX], Registers[R_RDX]));
		break;
	case VMX_EXIT_INVD:
		__wbinvd();
		break;
	case VMX_EXIT_XCPT_OR_NMI:
		//DbgPrint("Exception\n");
		break;
	default:
		DbgPrint("Unhandled VM Exit! Reason = %x\n", ExitReason);
		//ShowGuestState(Registers);
		//KeBugCheckEx(0xDEADBEEF, 0, 0, 0, 0);
		break;
	}

	/* Set next RIP */
	//DbgPrint("RIP = %016llX instruction len = %d cr3 = %016llX Add = %016llX\n", GuestRIP, ExitInstructionLength, cr3, reg);
	__vmx_vmwrite(GUEST_RIP, GuestRIP + ExitInstructionLength);

	return TRUE;
}
// }
/*
vm monitor guest
1.1 通过cpuid指令检查cpu是否支持VT:ecx.vmx第6位 如果为1，支持VT，否则不支持
1.2 通过特定的msr寄存器来确认是否支持VT
1.3 申请一块非分页内存，用来存放vmxon区域
1.4 初始化vmxon区域的版本编号
1.5 给cr0和cr4寄存器的特定位置位，满足：
IA32_VMX_CR0_FIXED0 寄存器中为1的位，在cr0中必须为1
IA32_VMX_CR0_FIXED1 寄存器中为0的位，在cr0中必须为0
IA32_VMX_CR4_FIXED0 寄存器中为1的位，在cr4中必须为1
IA32_VMX_CR4_FIXED1 寄存器中为0的位，在cr4中必须为0
1.6 确认IA32_FEATURE_CONTROL寄存器被正确置位







2、vmxon
3、vmclear
4、vmptrload
5、vmcs
6、vmlaunch
7、vmclear
8、vmoff




*/
//检查BIOS是否支持VT
BOOLEAN VmxIsSupportVTBIOS()
{
	ULONG64 value = __readmsr(IA32_FEATURE_CONTROL);
	return (value & 0x5) == 0x5;
}

//检查CPU是否支持VT
BOOLEAN VmxIsCheckSupportVTCPU()
{
	int cpuinfo[4];
	__cpuidex(cpuidinfo,1,0);
	//CPUID 是否支持VT ecx.vmx第6位 如果为1，支持VT，否则不支持
	return (cpuidinfo[2] >> 5) & 1;
}

//检查CR4VT是否开启，如果为1，代表已经开启过了
BOOLEAN VmxIsCheckSupportVTCr4()
{
	ULONG64 mcr4 = __readcr4();
	//检测CR4 VT是否开启，cr4.vmxe如果第14位为1，那么VT已经被开启，否则可以开启
	return ((mcr4 >> 13) & 1) == 0;
}
//--------------------------------------------------------------------

/*
1、检查是否支持VT：
1.1 CPU硬件是否支持VT
	作用：确认CPU是否支持VMX指令集（VT-x的硬件基础）
	原理：通过CPUID指令查询CPU功能标志，其中ECX寄存器的第5位（从0开始计数）为1，则CPU支持VT-x指令集
	代码：
		BOOLEAN VmxIsCheckSupportVTCPU()
		{
			int cpuinfo[4];  // 存储CPUID返回的EAX、EBX、ECX、EDX寄存器值
			// 执行CPUID指令：EAX=1（查询处理器基本功能），子功能号=0
			__cpuidex(cpuinfo, 1, 0);  // 注意：原代码变量名拼写错误（cpuidinfo→cpuinfo）
			// 检查ECX寄存器（cpuinfo[2]）的第5位（bit 5）：
			// (cpuinfo[2] >> 5) 将第5位移到最低位，&1判断该位是否为1
			return ( (cpuinfo[2] >> 5) & 1 );
		}

1.2 BIOS/UEFI是否支持VT
	作用：即使CPU支持VT，也需BIOS/UEFI中手动启动。通过读取IA32_FEATURE_CONTROL寄存器确认
	原理：IA32_FEATURE_CONTROL(地址：0x3A)是控制VT启动的关键寄存器，需同时满足：
		bit 0(锁定位)=1：BIOS 配置已锁定（确保生效）
		bit 2(VMX外部使能位)=1：允许在非SMX模式（不同模式）下启动VT
	代码：
		BOOLEAN VmxIsSupportVTBIOS()
		{
			// 读取IA32_FEATURE_CONTROL MSR（地址0x3A）的值
			ULONG64 value = __readmsr(IA32_FEATURE_CONTROL);  // 需定义IA32_FEATURE_CONTROL=0x3A
			// 检查bit 0和bit 2是否同时为1：0x5是二进制000...000101
			return (value & 0x5) == 0x5;
		}

1.3 Cr0 & Cr4：
	进入VT模式前，需要保证Cr0的PE位、PG位和NE位为1，即保证系统开启了保护模式和页保护模式，且启用了x87 协处理器错误的内部报告机制
	Cr4的VMXE位（第13位）是用户可控的，表示系统是否进入VT模式，进入VT模式前需要手动置1，否则会触发保护异常，且退出VT模式前无法更改该标志位。
	CR4寄存器的VMXE位是否未开启
	作用：确认CR4寄存器的VMXE位（bit13）是否未开启，确保可初始化VMX模式（该位需手动置1以进入VMX根模式）
	原理：CR4.VMXE是启用VMX操作的开关，置 1 后 CPU 才能执行VMXON等虚拟化指令。若该位已为 1，说明 VT-x 已处于初始化状态。
	代码：
		BOOLEAN VmxIsCheckSupportVTCr4()
		{
			// 读取CR4控制寄存器的值
			ULONG64 mcr4 = __readcr4();
			// 检查CR4的bit 13（VMXE位）是否为0：
			// (mcr4 >> 13) 将bit 13移到最低位，&1判断是否为0（未开启）
			return ( (mcr4 >> 13) & 1 ) == 0;
		}

1.4 完整检查代码：
	BOOLEAN IsVTxAvailable()
	{
		// 步骤1：CPU硬件支持
		if (!VmxIsCheckSupportVTCPU()) {
			return FALSE;
		}
		// 步骤2：BIOS启用
		if (!VmxIsSupportVTBIOS()) {
			return FALSE;
		}
		// 步骤3：CR4.VMXE未开启（可初始化）
		if (!VmxIsCheckSupportVTCr4()) {
			// 若已开启，仍可使用VT-x，但需确认状态（如是否已进入VMX根模式）
			// 此处返回TRUE或FALSE取决于业务需求（是否允许复用已有状态）
		}
		return TRUE;
	}

1.5 VT生命周期：
	1.5.1 软件通过执行VMXON指令进入VMX操作
	1.5.2 使用VM Entry，VMM可以将Guest输入到虚拟机中。VMM使用VMLAUNCH和VMRESUME指令开启虚拟机入口，并在需要时通过VM Exit重新获得控制权
    1.5.3 VM Exit传输信号到VMM指定的入口点，VMM可以针对虚拟机退出的原因采取相应的操作，然后使用VM Entry返回到虚拟机
	1.5.4 最终，VMM可能会决定关闭自己，并离开VMX的运行，它通过执行VMXOFF指令实现
	1.5.5：
		1.开锁（将Cr4的VMXE位置1）
		2.开柜门（VMXON）
		3.拔电源（VMCLEAR，相当于初始化）
		4.选中机器（VMPTRLOAD，选择需要处理的guest机）
		5.装机（设置VMCS，通过VMWRITE）
		6.开机（VMLAUNCH）
		7.拔电源（依然是VMCLEAR）
		8.关柜门（VMXOFF）
		9.关锁（将Cr4的VMXE位置0）

2、VMXON
2.1 申请一块4KB对齐的非分页内存，作为vmxon的参数
	PHYSICAL_ADDRESS lowphys,heiPhy;
	lowphys.QuadPart = 0;
	heiPhy.QuadPart = -1;
	pVcpu->VmxOnAddr = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, lowphys, heiPhy, lowphys, MmCached);

2.2 把msr中 IA32_VMX_BASIC 这个寄存器的低4字节填入vmxon的头4字节。否则vmxon的执行会出错。基本上这个寄存器的低4字节会是1。之后随着版本的更新可能会有变化。
	ULONG64 vmxBasic = __readmsr(IA32_VMX_BASIC);
	*(PULONG)pVcpu->VmxOnAddr = (ULONG)vmxBasic;

2.3 在设置完vmxon区域之后，还需最后一步即可vmxon。需要根据msr寄存器中的指示进行cr0和cr4寄存器的设置。简单解释就是在进行vmxon之前， IA32_VMX_CR0_FIXED0 寄存器中为1的值，在cr0中必须为1、 IA32_VMX_CR0_FIXED1 寄存器中为0的值，在cr0中必须为0。cr4同理。那么可以通过 cr0 = cr0 | IA32_VMX_CR0_FIXED0 & IA32_VMX_CR0_FIXED1 操作将cr0和cr4进行置位。
	ULONG64 vcr00 = __readmsr(IA32_VMX_CR0_FIXED0);
	ULONG64 vcr01 = __readmsr(IA32_VMX_CR0_FIXED1);
	ULONG64 vcr04 = __readmsr(IA32_VMX_CR4_FIXED0);
	ULONG64 vcr14 = __readmsr(IA32_VMX_CR4_FIXED1);

	ULONG64 mcr4 = __readcr4();
	ULONG64 mcr0 = __readcr0();

	mcr4 |= vcr04;
	mcr4 &= vcr14;
	mcr0 |= vcr00;
	mcr0 &= vcr01;

	__writecr0(mcr0);
	__writecr4(mcr4);

2.4 通过vmxon打开柜门
	int error = __vmx_on(&pVcpu->VmxOnAddrPhys.QuadPart);

3、VMCS
3.1 首先申请vmcs内存。和vmxon内存类似，这一块内存的头4个字节也要填入 IA32_VMX_BASIC 的低4个字节。vmcs中保存的是虚拟机的各种寄存器和控制区域、vmexit控制区域等。在装机过程中要通过vmwrite进行vmcs的设置。
	申请vmcs内存并设置头4字节为 IA32_VMX_BASIC 的低4字节之后，通过vmclear指令进行初始化。传入的参数与vmxon的参数类似，是指向申请的内存的物理地址的一个指针。vmclear的用法如下
	__vmx_vmclear(&pVcpu->VmxcsAddrPhys.QuadPart);

3.2 vmptrload（选中机器）：vmptrload 指令和vmxon、vmclear类似，传入的是指向vmcs结构的物理地址的一个指针。只有执行了这行指令之后才能通过 vmwrite 进行vmcs结构的填写
	__vmx_vmptrld(&pVcpu->VmxcsAddrPhys.QuadPart);

3.3 设置VMCS，需要设置的VMCS字段：
	Guest state fields
	Host state fields
	vm-control fields
		vm execution control
		vm exit control
		vm entry control
	除这5个区域之外，vmcs还有一个区域是vm exit信息区域。这个区域是只读的，存储的是vmx指令失败后失败代码的编号。
3.3.1 需要设置的VMCS字段：
	1、Guest state fields，在VT从虚拟机中退出时，处理器的状态（寄存器等）会被存储在该区域中。而进入虚拟机（开启VT）时，虚拟机中的各种处理器的状态都由进入虚拟机时该区域的对应字段的值来决定。
	2、Host state fields，在从虚拟机中退出时，host对CPU进行接管。host接管后各种寄存器的状态存储在这个区域。也就是说当虚拟机中发生了vm-exit事件，CPU会从guest返回到host，这个区域中的值会被设置到对应的寄存器中，然后按照设置完之后的eip继续执行。
	
3.4 guest区域填充：
		GDT表项属性的分离与填充（es cs ss ds fs gs ldtr）
		tr寄存器gdt表项的填充
3.5 host区域填充

3.6 vm-control相应字段的设置：
	VM_ENTRY_CONTROLS字段
	MSR-load字段
	VM_ENTRY_INTR_INFO_FIELD字段
	vm-exit control字段
	vm-execution control字段
	pin-based vm-execution control字段
	processor-based vm-execution control字段

	处理vmx指令导致的vm-exit事件
	处理cpuid导致的vm-exit事件
	处理getsec invd xsetbv导致的vm-exit事件
	guest与host的通信&&关闭VT
*/
