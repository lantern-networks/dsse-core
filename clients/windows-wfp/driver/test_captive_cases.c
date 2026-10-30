/* Host harness inputs; compiled with the actual driver functions above. */
static FWPS_INCOMING_VALUES v;
static FWPS_INCOMING_METADATA_VALUES m;
static ARRAY16 a6,b6;
static void input(int layer,UINT64 flow,UINT64 endpoint,int protocol,int remotePort,int flags,int reason){
    memset(&v,0,sizeof(v));memset(&m,0,sizeof(m));v.layerId=layer;
    m.currentMetadataValues=15;m.flowHandle=flow;m.transportEndpointHandle=endpoint;m.compartmentId=1;m.processId=42;
    v.incomingValue[0].value.type=v.incomingValue[1].value.type=FWP_UINT32;
    v.incomingValue[0].value.uint32=0xc0000201;v.incomingValue[1].value.uint32=0xc0000202;
    if(!(layer%2)){memset(&a6,0,sizeof(a6));memset(&b6,0,sizeof(b6));a6.byteArray16[0]=b6.byteArray16[0]=0x20;a6.byteArray16[15]=1;b6.byteArray16[15]=2;
        v.incomingValue[0].value.type=v.incomingValue[1].value.type=FWP_BYTE_ARRAY16_TYPE;v.incomingValue[0].value.byteArray16=&a6;v.incomingValue[1].value.byteArray16=&b6;}
    v.incomingValue[2].value.type=v.incomingValue[3].value.type=FWP_UINT16;v.incomingValue[2].value.uint16=40000;v.incomingValue[3].value.uint16=remotePort;
    v.incomingValue[4].value.type=FWP_UINT8;v.incomingValue[4].value.uint8=protocol;
    v.incomingValue[5].value.type=v.incomingValue[6].value.type=FWP_UINT32;v.incomingValue[5].value.uint32=flags;v.incomingValue[6].value.uint32=reason;
}
static void decision(int blocked){FWPS_CLASSIFY_OUT out={1,0};DsseCaptiveClassify(&v,&m,0,0,0,0,&out);assert(out.actionType==(blocked?20:10));assert(out.rights==(blocked?0:1));}
static void established(void){FWPS_CLASSIFY_OUT out={1,0};DsseCaptiveFlowClassify(&v,&m,0,0,0,0,&out);assert(out.actionType==10);}
int main(void){
    InitializeListHead(&g_captiveFlowList);for(int i=0;i<256;i++)InitializeListHead(&g_captiveFlowBuckets[i]);
    assert(!dsseCaptiveArm(&g_captive,100,100,0,1,0));assert(!dsseCaptiveArm(&g_captive,100,100,1,0,0));
    assert(!dsseCaptiveArm(&g_captive,100,100,1,1,1));assert(!dsseCaptiveArm(&g_captive,~0ULL-1,2,1,1,0));
    now100ns=100;assert(dsseCaptiveArm(&g_captive,100,100,1,1,0));UINT64 gen=g_captive.Generation;
    assert(dsseCaptiveArm(&g_captive,150,9999,1,1,0));assert(g_captive.Deadline100ns==200);
    for(int layer=1;layer<=4;layer++){input(layer,11+layer,100+layer,6,443,0,0);decision(0);}
    /* Actual FLOW_ESTABLISHED record, with no fixed connection count budget. */
    input(5,11,111,6,443,0,0);established();assert(allocations==1);
    established();assert(allocations==1); /* informational duplicate is NOT an association */
    input(6,12,112,17,443,0,0);established();assert(allocations==2);
    now100ns=200;
    for(int layer=1;layer<=4;layer++){input(layer,100+layer,200+layer,6,443,0,0);decision(1);v.incomingValue[5].value.uint32=1;decision(0);}
    input(1,11,111,6,443,2,1);decision(0);assert(dsseCaptiveNativeReauth(&v,&m));
    input(2,12,112,17,443,2,1);decision(0);assert(dsseCaptiveNativeReauth(&v,&m));
    /* Same UDP socket, new peer; known flow mismatch cannot use reason fallback. */
    v.incomingValue[1].value.byteArray16->byteArray16[15]=3;decision(1);
    input(2,13,112,17,443,0,0);decision(1);
    input(1,11,999,6,443,2,1);decision(1); /* endpoint reuse */
    input(1,11,111,6,444,2,1);decision(1); /* tuple mismatch */
    input(1,11,111,6,443,2,16|1);decision(1);assert(!dsseCaptiveNativeReauth(&v,&m));
    input(1,90,190,6,443,2,1);decision(0); /* existed before driver/filter */
    input(1,91,191,6,443,2,0);decision(1); /* flag alone is not evidence */
    input(1,91,191,6,443,2,16);decision(1); /* pending initial connect */
    input(1,91,191,6,443,2,16|1|64);decision(1);
    input(1,91,191,6,443,2,512);decision(1); /* unknown/new multicast reason */
    input(1,0,191,6,443,2,1);decision(1);
    /* Only network control, even if metadata has no flow yet. */
    input(1,0,0,17,67,0,0);v.incomingValue[2].value.uint16=68;decision(0);
    input(2,0,0,17,547,0,0);v.incomingValue[2].value.uint16=546;decision(0);
    input(2,0,0,58,0,0,0);v.incomingValue[2].value.uint16=135;decision(0);
    v.incomingValue[2].value.uint16=128;decision(1);
    input(1,0,0,17,53,0,0);decision(1);
    /* Recovery: exact agent process and signed-profile TCP Edge destination. */
    input(1,30,130,6,8443,0,0);DSSE_CAPTIVE_KEY k;UINT32 flags,reason;assert(dsseCaptiveKey(&v,&m,&k,&flags,&reason));
    g_captiveAgentPid=42;g_captiveEdgeCount=1;g_captiveEdges[0].Family=2;g_captiveEdges[0].Port=8443;memcpy(g_captiveEdges[0].Addr,k.Remote,16);decision(0);
    m.processId=43;decision(1);m.processId=42;v.incomingValue[3].value.uint16=443;decision(1);
    v.incomingValue[3].value.uint16=8443;g_captiveAgentPid=0;decision(1); /* owner exited/PID reused */
    /* Allocation loss must not cut an established flow during or after FINISH. */
    allocationFail=1;input(5,50,150,17,443,0,0);established();allocationFail=0;
    input(1,50,150,17,443,2,1);decision(0);assert(dsseCaptiveNativeReauth(&v,&m));
    assert(!dsseCaptiveFinish(&g_captive,gen+1,1,1));assert(!dsseCaptiveFinish(&g_captive,gen,1,0));
    assert(dsseCaptiveFinish(&g_captive,gen,1,1));assert(dsseCaptiveNativeReauth(&v,&m));
    input(2,12,112,17,443,2,1);assert(dsseCaptiveNativeReauth(&v,&m));
    endFlow(11);endFlow(12);assert(allocations==0&&IsListEmpty(&g_captiveFlowList));
    assert(dsseCaptiveArm(&g_captive,300,1,1,1,0));now100ns=301;
    input(1,11,111,6,443,0,0);decision(1); /* identical tuple reused is NEW */
    dsseCaptiveRecover(&g_captive);decision(0);
    for(int mode=0;mode<4;mode++){
        g_captiveFlowRundown=0;input(5,200+mode,300+mode,6,443,0,0);established();assert(allocations==1);
        removalMode=mode;removalCalls=0;drainContexts();assert(allocations==0&&IsListEmpty(&g_captiveFlowList));
        assert(removalCalls==(mode==3?2:1));
    }
    assert(unexpectedReports==1);
    g_captive.Generation=~0ULL;assert(!dsseCaptiveArm(&g_captive,400,1,1,1,0));
    puts("actual ALE admission and WFP flow lifetime model passed");return 0;
}
