
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "captive_deadline.h"
#include "captive_admission.h"
#define NTAPI
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define TRUE 1
#define FALSE 0
#define MAXUINT32 UINT32_MAX
#define AF_INET 2
#define AF_INET6 23
#define IPPROTO_TCP 6
#define FWPS_RIGHT_ACTION_WRITE 1
#define FWP_CONDITION_FLAG_IS_LOOPBACK 1
#define FWP_CONDITION_FLAG_IS_REAUTHORIZE 2
#define FWP_CONDITION_REAUTHORIZE_REASON_CLASSIFY_COMPLETION 16
#define FWP_ACTION_CONTINUE 10
#define FWP_ACTION_BLOCK 20
#define FWPS_METADATA_FIELD_FLOW_HANDLE 1
#define FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE 2
#define FWPS_METADATA_FIELD_COMPARTMENT_ID 4
#define FWPS_METADATA_FIELD_PROCESS_ID 8
#define FWPS_IS_METADATA_FIELD_PRESENT(m,b) (((m)->currentMetadataValues&(b))!=0)
#define FWP_UINT8 1
#define FWP_UINT16 2
#define FWP_UINT32 3
#define FWP_BYTE_ARRAY16_TYPE 4
#define POOL_FLAG_NON_PAGED 0
#define IO_NO_INCREMENT 0
#define STATUS_SUCCESS 0
#define STATUS_PENDING 0x103
#define STATUS_UNSUCCESSFUL (-1)
#define Executive 0
#define KernelMode 0
#define DPFLTR_IHVNETWORK_ID 0
#define DPFLTR_ERROR_LEVEL 0
#define STATUS_OBJECT_NAME_EXISTS 0x40000000
#define NT_SUCCESS(s) ((s)>=0)
typedef struct { long long QuadPart; } LARGE_INTEGER;
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef uintptr_t ULONG_PTR;
typedef int BOOLEAN, LONG, NTSTATUS, KLOCK_QUEUE_HANDLE, KSPIN_LOCK, KEVENT, EX_RUNDOWN_REF;
typedef struct { UINT8 byteArray16[16]; } ARRAY16;
typedef struct { int type; UINT8 uint8; UINT16 uint16; UINT32 uint32; ARRAY16* byteArray16; } VALUE;
typedef struct { UINT16 layerId; struct { VALUE value; } incomingValue[9]; } FWPS_INCOMING_VALUES;
typedef struct { UINT64 currentMetadataValues,flowHandle,transportEndpointHandle,processId; UINT32 compartmentId; } FWPS_INCOMING_METADATA_VALUES;
typedef int FWPS_FILTER;
typedef struct { UINT32 rights; int actionType; } FWPS_CLASSIFY_OUT;
typedef struct _LIST_ENTRY { struct _LIST_ENTRY *Flink,*Blink; } LIST_ENTRY;
#define CONTAINING_RECORD(p,t,f) ((t*)((char*)(p)-offsetof(t,f)))
static void InitializeListHead(LIST_ENTRY* h){h->Flink=h->Blink=h;}
static int IsListEmpty(LIST_ENTRY* h){return h->Flink==h;}
static void InsertTailList(LIST_ENTRY* h,LIST_ENTRY* e){e->Flink=h;e->Blink=h->Blink;h->Blink->Flink=e;h->Blink=e;}
static void RemoveEntryList(LIST_ENTRY* e){e->Blink->Flink=e->Flink;e->Flink->Blink=e->Blink;}
static void KeAcquireInStackQueuedSpinLock(int* l,int* q){(void)l;*q=0;}
static void KeReleaseInStackQueuedSpinLock(int* q){(void)q;}
static void KeSetEvent(int* e,int p,int w){(void)p;(void)w;*e=1;}
static void KeClearEvent(int* e){*e=0;}
static int ExAcquireRundownProtection(int* r){return !*r;}
static void ExReleaseRundownProtection(int* r){(void)r;}
static void ExWaitForRundownProtectionRelease(int* r){*r=1;}
static int InterlockedIncrement(int* n){return ++*n;}
static int InterlockedDecrement(int* n){return --*n;}
static int InterlockedExchange(volatile int* n,int v){int old=*n;*n=v;return old;}
static int InterlockedCompareExchange(volatile int* n,int v,int c){int old=*n;if(old==c)*n=v;return old;}
#define RtlZeroMemory(p,n) memset(p,0,n)
#define RtlCopyMemory(p,q,n) memcpy(p,q,n)
static size_t RtlCompareMemory(const void* p,const void* q,size_t n){return memcmp(p,q,n)==0?n:0;}
static UINT32 RtlUlongByteSwap(UINT32 v){return __builtin_bswap32(v);}
static int allocationFail,allocations;
static void* ExAllocatePool2(int f,size_t n,int tag){(void)f;(void)tag;if(allocationFail)return 0;allocations++;return calloc(1,n);}
static void ExFreePoolWithTag(void* p,int tag){(void)tag;allocations--;free(p);}
static UINT64 now100ns;
static UINT64 KeQueryInterruptTime(void){return now100ns;}
static int g_policyLock,g_policyValid;
static DSSE_CAPTIVE_STATE g_captive;
typedef struct {UINT32 Family;UINT8 Addr[16];UINT16 Port,pad;} DSSE_DEST_RULE;
static DSSE_DEST_RULE g_captiveEdges[32];
static UINT32 g_captiveEdgeCount;
static UINT64 g_captiveAgentPid;
static UINT32 g_captiveFlowCallouts[2]={101,102};
static void NTAPI DsseCaptiveFlowDelete(UINT16,UINT32,UINT64);
static struct {UINT64 flow,context;UINT16 layer;UINT32 callout;} contexts[64];
static NTSTATUS FwpsFlowAssociateContext(UINT64 f,UINT16 l,UINT32 c,UINT64 context){
    for(int i=0;i<64;i++)if(contexts[i].flow==f&&contexts[i].context)return STATUS_OBJECT_NAME_EXISTS;
    for(int i=0;i<64;i++)if(!contexts[i].context){contexts[i].flow=f;contexts[i].layer=l;contexts[i].callout=c;contexts[i].context=context;return 0;}abort();
}
static void endFlow(UINT64 f){for(int i=0;i<64;i++)if(contexts[i].flow==f&&contexts[i].context){UINT64 c=contexts[i].context;contexts[i].context=0;DsseCaptiveFlowDelete(contexts[i].layer,contexts[i].callout,c);}}

#define FWPS_LAYER_ALE_AUTH_CONNECT_V4 1
#define FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS 0
#define FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS 1
#define FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT 2
#define FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT 3
#define FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL 4
#define FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS 5
#define FWPS_FIELD_ALE_AUTH_CONNECT_V4_REAUTHORIZE_REASON 6

#define FWPS_LAYER_ALE_AUTH_CONNECT_V6 2
#define FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS 0
#define FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS 1
#define FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT 2
#define FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT 3
#define FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL 4
#define FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS 5
#define FWPS_FIELD_ALE_AUTH_CONNECT_V6_REAUTHORIZE_REASON 6

#define FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 3
#define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS 0
#define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS 1
#define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT 2
#define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT 3
#define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL 4
#define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_FLAGS 5
#define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_REAUTHORIZE_REASON 6

#define FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6 4
#define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS 0
#define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS 1
#define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT 2
#define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT 3
#define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL 4
#define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_FLAGS 5
#define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_REAUTHORIZE_REASON 6

#define FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4 5
#define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS 0
#define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS 1
#define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT 2
#define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT 3
#define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL 4
#define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_FLAGS 5
#define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_REAUTHORIZE_REASON 6

#define FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6 6
#define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS 0
#define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS 1
#define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT 2
#define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT 3
#define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL 4
#define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_FLAGS 5
#define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_REAUTHORIZE_REASON 6

/* Removal modes exercise actual teardown: synchronous success, deferred delete,
 * natural-delete race, and an unexpected recoverable API error. */
static int removalMode,removalCalls,unexpectedReports;
static UINT64 deferredDelete;
static NTSTATUS FwpsFlowRemoveContext(UINT64 flow,UINT16 layer,UINT32 callout){
    (void)layer;(void)callout;removalCalls++;
    if(removalMode==3){removalMode=0;return -55;}
    if(removalMode==1||removalMode==2){deferredDelete=flow;return removalMode==1?STATUS_PENDING:STATUS_UNSUCCESSFUL;}
    endFlow(flow);return STATUS_SUCCESS;
}
static int KeWaitForSingleObject(int* event,int why,int mode,int alert,LARGE_INTEGER* delay){
    (void)event;(void)why;(void)mode;(void)alert;assert(delay&&delay->QuadPart<0);
    if(deferredDelete){UINT64 f=deferredDelete;deferredDelete=0;endFlow(f);}return 0;
}
static void DbgPrintEx(int component,int level,const char* format,int status){
    (void)component;(void)level;(void)format;assert(status==-55);unexpectedReports++;
}
