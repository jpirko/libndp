#include <gtest/gtest.h>
#include <mockcpp/mockcpp.hpp>

extern "C" {
#include <stdlib.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <poll.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include "ndp.h"
#include "ndp_private.h"
}

TEST(TestOpen, openSuccess)
{
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);
    ndp_close(ndp);
}

TEST(TestOpen, openFailByCallocFail)
{
    MOCKER(calloc).stubs().will(returnValue((void *)nullptr));
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_NE(ret, 0);
    GlobalMockObject::verify();
}

TEST(TestOpen, setLogPriorityErr)
{
    char *str = "err";
    MOCKER(getenv).stubs().will(returnValue(str));
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);
    ndp_close(ndp);
    GlobalMockObject::verify();
}

TEST(TestOpen, setLogPriorityInfo)
{
    char *str = "info";
    MOCKER(getenv).stubs().will(returnValue(str));
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);
    ndp_close(ndp);
    GlobalMockObject::verify();
}

TEST(TestOpen, setLogPriorityDebug)
{
    char *str = "debug";
    MOCKER(getenv).stubs().will(returnValue(str));
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);
    ndp_close(ndp);
    GlobalMockObject::verify();
}

TEST(TestOpen, setLogPriorityXXX)
{
    char *str = "XXX";
    MOCKER(getenv).stubs().will(returnValue(str));
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);
    ndp_close(ndp);
    GlobalMockObject::verify();
}

TEST(TestLog, setLogPriorityErr)
{
    char *endprt = "\0";
    char *str = "debug";
    MOCKER(getenv).stubs().will(returnValue(str));
    MOCKER(strtol).stubs().with(any(), outBoundP(&endprt, sizeof(endprt)), any()).will(returnValue(-1));
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);
    GlobalMockObject::verify();
}

TEST(TestLog, setLogPriority)
{
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    ndp_set_log_priority(ndp, 4);
    ndp_close(ndp);
}

TEST(TestLog, getLogPriority)
{
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    ndp_set_log_priority(ndp, 5);
    ret = ndp_get_log_priority(ndp);
    EXPECT_EQ(ret, 5);
    ndp_close(ndp);
}

TEST(TestLog, testNdpLog)
{
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    ndp_log(ndp, 5, "test_file.log", __LINE__, __func__, "test log");
    ndp_close(ndp);
}

TEST(TestLog, setLogFunc)
{
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    void (*log_fn)(struct ndp *ndp, int priority,
                   const char *file, int line, const char *fn,
                   const char *format, va_list args);
    ndp_set_log_fn(ndp, log_fn);
    ndp_close(ndp);
}

int my_socket(int af, int type, int protocol)
{
    errno = -1;
    return -1;
}

TEST(TestOpen, openFailByNdpSockOpenFail)
{
    MOCKER(socket).stubs().will(invoke(my_socket));
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_NE(ret, 0);
    GlobalMockObject::verify();
}

TEST(TestClose, closeSuccess)
{
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);
    ndp_close(ndp);
}

TEST(TestNdpSockOpen, callSocketFail)
{
    MOCKER(socket).stubs().will(invoke(my_socket));
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_NE(ret, 0);
    GlobalMockObject::verify();
}

TEST(TestNdpSockOpen, callSetSockOptIPv6RecvpktinfoFail)
{
    MOCKER(setsockopt).stubs().with(any(), any(), eq(49),
		    any(), any()).will(returnValue(-1));
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_NE(ret, 0);
    GlobalMockObject::verify();
}

TEST(TestNdpSockOpen, callSetSockIPv6MukticastHopsFail)
{
    MOCKER(setsockopt).stubs().with(any(), any(), eq(49),
		    any(), any()).will(returnValue(0));
    MOCKER(setsockopt).stubs().with(any(), any(), eq(18),
		    any(), any()).will(returnValue(-1));
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_NE(ret, 0);
    GlobalMockObject::verify();
}

TEST(TestNdpSockOpen, callSetSockIPv6RecvhoplLimitFail)
{
    MOCKER(setsockopt).stubs().with(any(), any(), eq(49),
		    any(), any()).will(returnValue(0));
    MOCKER(setsockopt).stubs().with(any(), any(), eq(18),
		    any(), any()).will(returnValue(0));
    MOCKER(setsockopt).stubs().with(any(), any(), eq(51),
		    any(), any()).will(returnValue(-1));
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_NE(ret, 0);
    GlobalMockObject::verify();
}

TEST(TestNdpSockOpen, callSetSockIcmp6FilterFail)
{
    MOCKER(setsockopt).stubs().with(any(), any(), eq(49),
		    any(), any()).will(returnValue(0));
    MOCKER(setsockopt).stubs().with(any(), any(), eq(18),
		    any(), any()).will(returnValue(0));
    MOCKER(setsockopt).stubs().with(any(), any(), eq(51),
		    any(), any()).will(returnValue(0));
    MOCKER(setsockopt).stubs().with(any(), any(), eq(1),
		    any(), any()).will(returnValue(-1));
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_NE(ret, 0);
    GlobalMockObject::verify();
}

TEST(TestNdpCallEventFd, basicTest)
{
    struct ndp *ndp;
    int ret = ndp_call_eventfd_handler(ndp);
    EXPECT_NE(ret, 0);
}

TEST(TestNdpCallallEventFd, pollNotReady)
{
    struct ndp *ndp;
    int ret = ndp_callall_eventfd_handler(ndp);
    EXPECT_EQ(ret, 0);
}

TEST(TestNdpCallallEventFd, pollReady)
{
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);
    ret = ndp_callall_eventfd_handler(ndp);
    EXPECT_EQ(ret, 0);
    ndp_close(ndp);
}

TEST(TestNdpCallallEventFd, pollFail)
{
    errno = 0;
    MOCKER(poll).stubs().will(returnValue(-1));
    struct ndp *ndp;
    int ret = ndp_callall_eventfd_handler(ndp);
    EXPECT_EQ(ret, 0);
    GlobalMockObject::verify();
}

int my_poll(struct pollfd *pfd, int, int)
{
    pfd->revents = 1;
    return 0;
}

TEST(TestNdpCallallEventFd, NdpCallEventFdFail)
{
    MOCKER(ndp_call_eventfd_handler).stubs().will(returnValue(-1));
    MOCKER(poll).stubs().will(invoke(my_poll));
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);
    ret = ndp_callall_eventfd_handler(ndp);
    EXPECT_EQ(ret, -1);
    ndp_close(ndp);
    GlobalMockObject::verify();
}

TEST(TestAllocNdpMsg, allocRS)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);
    ndp_msg_destroy(msg);
}

TEST(TestAllocNdpMsg, allocRA)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RA;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);
    ndp_msg_destroy(msg);
}

TEST(TestAllocNdpMsg, allocNS)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_NS;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);
    ndp_msg_destroy(msg);
}

TEST(TestAllocNdpMsg, allocNA)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_NA;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);
    ndp_msg_destroy(msg);
}

TEST(TestAllocNdpMsg, allocR)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_R;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);
    ndp_msg_destroy(msg);
}

TEST(TestAllocNdpMsg, allocAll)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_ALL;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_NE(ret, 0);
}

TEST(TestAllocNdpMsg, allocFail)
{
    MOCKER(calloc).stubs().will(returnValue((void *)nullptr));
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_NS;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_NE(ret, 0);
    GlobalMockObject::verify();
}

TEST(TestPayload, setPayloadLen)
{
    struct ndp_msg *msg;
    size_t len;
    enum ndp_msg_type msg_type = NDP_MSG_NS;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    len = 2000;
    ndp_msg_payload_len_set(msg, len);

    ndp_msg_destroy(msg);
}

TEST(TestPayload, payloadOffset)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_NS;
    
    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ndp_msg_opt_slladdr(msg, 16);

    ndp_msg_destroy(msg);
}

TEST(TestGetMsg, GetRsSucc)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;
    struct ndp_msgrs *ptr;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ptr = ndp_msgrs(msg);
    EXPECT_NE(ptr, nullptr);

    ndp_msg_destroy(msg);
}

TEST(TestGetMsg, GetRsFail)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RA;
    struct ndp_msgrs *ptr;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ptr = ndp_msgrs(msg);
    EXPECT_EQ(ptr, nullptr);

    ndp_msg_destroy(msg);
}

TEST(TestGetMsg, GetRaSucc)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RA;
    struct ndp_msgra *ptr;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ptr = ndp_msgra(msg);
    EXPECT_NE(ptr, nullptr);

    ndp_msg_destroy(msg);
}

TEST(TestGetMsg, GetRaFail)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;
    struct ndp_msgra *ptr;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ptr = ndp_msgra(msg);
    EXPECT_EQ(ptr, nullptr);

    ndp_msg_destroy(msg);
}

TEST(TestGetMsg, GetNsSucc)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_NS;
    struct ndp_msgns *ptr;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ptr = ndp_msgns(msg);
    EXPECT_NE(ptr, nullptr);

    ndp_msg_destroy(msg);
}

TEST(TestGetMsg, GetNsFail)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_NA;
    struct ndp_msgns *ptr;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ptr = ndp_msgns(msg);
    EXPECT_EQ(ptr, nullptr);

    ndp_msg_destroy(msg);
}

TEST(TestGetMsg, GetNaSucc)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_NA;
    struct ndp_msgna *ptr;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ptr = ndp_msgna(msg);
    EXPECT_NE(ptr, nullptr);

    ndp_msg_destroy(msg);
}

TEST(TestGetMsg, GetNaFail)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_NS;
    struct ndp_msgna *ptr;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ptr = ndp_msgna(msg);
    EXPECT_EQ(ptr, nullptr);

    ndp_msg_destroy(msg);
}

TEST(TestGetMsg, GetRSucc)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_R;
    struct ndp_msgr *ptr;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ptr = ndp_msgr(msg);
    EXPECT_NE(ptr, nullptr);

    ndp_msg_destroy(msg);
}

TEST(TestGetMsg, GetRFail)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RA;
    struct ndp_msgr *ptr;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ptr = ndp_msgr(msg);
    EXPECT_EQ(ptr, nullptr);

    ndp_msg_destroy(msg);
}

TEST(TestMsg, getAddrTo)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;
    struct in6_addr *ptr;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ptr = ndp_msg_addrto(msg);
    EXPECT_NE(ptr, nullptr);

    ndp_msg_destroy(msg);
}

TEST(TestMsgra, SetAndGetCurhoplimit)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RA;
    struct ndp_msgra *msgra_ptr;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);
    
    msgra_ptr = ndp_msgra(msg);
    EXPECT_NE(msgra_ptr, nullptr);

    ndp_msgra_curhoplimit_set(msgra_ptr, 15);

    ret = ndp_msgra_curhoplimit(msgra_ptr);
    EXPECT_EQ(ret, 15);

    ndp_msg_destroy(msg);
}

TEST(TestMsgra, SetAndGetFlag)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RA;
    struct ndp_msgra *msgra_ptr;
    bool flag;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    msgra_ptr = ndp_msgra(msg);
    EXPECT_NE(msgra_ptr, nullptr);

    ndp_msgra_flag_managed_set(msgra_ptr, true);
    flag = ndp_msgra_flag_managed(msgra_ptr);
    EXPECT_TRUE(flag);

    ndp_msgra_flag_managed_set(msgra_ptr, false);
    flag = ndp_msgra_flag_managed(msgra_ptr);
    EXPECT_FALSE(flag);

    ndp_msgra_flag_other_set(msgra_ptr, true);
    flag = ndp_msgra_flag_other(msgra_ptr);
    EXPECT_TRUE(flag);

    ndp_msgra_flag_other_set(msgra_ptr, false);
    flag = ndp_msgra_flag_other(msgra_ptr);
    EXPECT_FALSE(flag);

    ndp_msgra_flag_home_agent_set(msgra_ptr, true);
    flag = ndp_msgra_flag_home_agent(msgra_ptr);
    EXPECT_TRUE(flag);

    ndp_msgra_flag_home_agent_set(msgra_ptr, false);
    flag = ndp_msgra_flag_home_agent(msgra_ptr);
     EXPECT_FALSE(flag);

    ndp_msg_destroy(msg);
}

TEST(TestMsgra, SetAndGetRoutePrf)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RA;
    struct ndp_msgra *msgra_ptr;
    enum ndp_route_preference prf;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    msgra_ptr = ndp_msgra(msg);
    EXPECT_NE(msgra_ptr, nullptr);

    ndp_msgra_route_preference_set(msgra_ptr, NDP_ROUTE_PREF_LOW);
    prf = ndp_msgra_route_preference(msgra_ptr);
    EXPECT_EQ(prf, 0);

    ndp_msgra_route_preference_set(msgra_ptr, NDP_ROUTE_PREF_MEDIUM);
    prf = ndp_msgra_route_preference(msgra_ptr);
    EXPECT_EQ(prf, NDP_ROUTE_PREF_MEDIUM);

    ndp_msgra_route_preference_set(msgra_ptr, NDP_ROUTE_PREF_HIGH);
    prf = ndp_msgra_route_preference(msgra_ptr);
    EXPECT_EQ(prf, 0);

    ndp_msg_destroy(msg);
}

TEST(TestMsgra, SetAndGetTime)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RA;
    struct ndp_msgra *msgra_ptr;
    uint16_t time;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    msgra_ptr = ndp_msgra(msg);
    EXPECT_NE(msgra_ptr, nullptr);

    ndp_msgra_router_lifetime_set(msgra_ptr, 215);
    time = ndp_msgra_router_lifetime(msgra_ptr);
    EXPECT_EQ(time, 215);

    ndp_msgra_reachable_time_set(msgra_ptr, 215);
    time = ndp_msgra_reachable_time(msgra_ptr);
    EXPECT_EQ(time, 215);

    ndp_msgra_retransmit_time_set(msgra_ptr, 215);
    time = ndp_msgra_retransmit_time(msgra_ptr);
    EXPECT_EQ(time, 215);

    ndp_msg_destroy(msg);
}

TEST(TestMsgna, SetAndGetFlag)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_NA;
    struct ndp_msgna *msgna_ptr;
    bool flag;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    msgna_ptr = ndp_msgna(msg);
    EXPECT_NE(msgna_ptr, nullptr);

    ndp_msgna_flag_router_set(msgna_ptr, true);
    flag = ndp_msgna_flag_router(msgna_ptr);
    EXPECT_TRUE(flag);

    ndp_msgna_flag_router_set(msgna_ptr, false);
    flag = ndp_msgna_flag_router(msgna_ptr);
    EXPECT_FALSE(flag);

    ndp_msgna_flag_solicited_set(msgna_ptr, true);
    flag = ndp_msgna_flag_solicited(msgna_ptr);
    EXPECT_TRUE(flag);

    ndp_msgna_flag_solicited_set(msgna_ptr, false);
    flag = ndp_msgna_flag_solicited(msgna_ptr);
    EXPECT_FALSE(flag);

    ndp_msgna_flag_override_set(msgna_ptr, true);
    flag = ndp_msgna_flag_override(msgna_ptr);
    EXPECT_TRUE(flag);

    ndp_msgna_flag_override_set(msgna_ptr, false);
    flag = ndp_msgna_flag_override(msgna_ptr);
    EXPECT_FALSE(flag);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, nextOptOffset)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;
    enum ndp_msg_opt_type opt_type = NDP_MSG_OPT_ROUTE;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ndp_msg_payload_opts_len(msg);

    ret = ndp_msg_next_opt_offset(msg, -1, opt_type);
    EXPECT_EQ(ret, -1);

    ndp_msg_payload_len_set(msg, 32);
    ret = ndp_msg_next_opt_offset(msg, -1, opt_type);
    EXPECT_EQ(ret, -1);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, getSllAddrLen)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);
    
    ret = ndp_msg_opt_slladdr_len(msg, 0);
    EXPECT_EQ(ret, 6);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, getTllAddr)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;
    unsigned char *linkaddr;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    linkaddr = ndp_msg_opt_tlladdr(msg, 0);
    EXPECT_NE(linkaddr, nullptr);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, getTllAddrLen)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ret = ndp_msg_opt_tlladdr_len(msg, 0);
    EXPECT_EQ(ret, 6);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, getPrefixAddr)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;
    struct in6_addr *ptr;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ptr = ndp_msg_opt_prefix(msg, 0);
    EXPECT_NE(ptr, nullptr);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, getPrefixLen)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ret = ndp_msg_opt_prefix_len(msg, 0);
    EXPECT_EQ(ret, 0);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, getPrefixValidTime)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ret = ndp_msg_opt_prefix_valid_time(msg, 0);
    EXPECT_EQ(ret, 0);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, getPrefixPreferredTime)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ret = ndp_msg_opt_prefix_preferred_time(msg, 0);
    EXPECT_EQ(ret, 0);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, getPrefixFlag)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;
    bool flag;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    flag = ndp_msg_opt_prefix_flag_on_link(msg, 0);
    EXPECT_FALSE(flag);

    flag = ndp_msg_opt_prefix_flag_auto_addr_conf(msg, 0);
    EXPECT_FALSE(flag);

    flag = ndp_msg_opt_prefix_flag_router_addr(msg, 0);
    EXPECT_FALSE(flag);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, getMtu)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ret = ndp_msg_opt_mtu(msg, 0);
    EXPECT_EQ(ret, 0);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, getRoutePrefixLen)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ret = ndp_msg_opt_route_prefix_len(msg, 0);
    EXPECT_EQ(ret, 0);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, getRouteLifetime)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ret = ndp_msg_opt_route_lifetime(msg, 0);
    EXPECT_EQ(ret, 0);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, getRoutePreference)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ret = ndp_msg_opt_route_preference(msg, 0);
    EXPECT_EQ(ret, 0);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, getRDnssLifetime)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ret = ndp_msg_opt_rdnss_lifetime(msg, 0);
    EXPECT_EQ(ret, 0);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, getRDnssAddr)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;
    struct in6_addr *ptr;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ptr = ndp_msg_opt_rdnss_addr(msg, 0, 0);
    EXPECT_NE(ptr, nullptr);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, getDnsslLifetime)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ret = ndp_msg_opt_dnssl_lifetime(msg, 0);
    EXPECT_EQ(ret, 0);

    ndp_msg_destroy(msg);
}

TEST(TestMsgOpt, getDnsslDomain)
{
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;
    char *ptr;

    int ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ptr = ndp_msg_opt_dnssl_domain(msg, 0, 0);
    EXPECT_EQ(ptr, nullptr);

    ndp_msg_destroy(msg);
}

int get_if_index()
{
    int index = 0;
    struct ifaddrs *ifa = NULL, *ifList;

    if (getifaddrs(&ifList) < 0)
    {
        return -1;
    }

    for (ifa = ifList; ifa != NULL; ifa = ifa->ifa_next)
    {
        if(ifa->ifa_addr->sa_family == AF_INET6 && strcmp(ifa->ifa_name, "lo") != 0)
        {
	    index = if_nametoindex(ifa->ifa_name);
	    break;
        }
    }

    freeifaddrs(ifList);
    return index;
}

TEST(TestSendNdp, msgTypeIsRs)
{
    struct ndp *ndp;
    int index;
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;
    struct in6_addr target = IN6ADDR_ANY_INIT;
    struct in6_addr dest = IN6ADDR_ANY_INIT;

    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    index = get_if_index();
    EXPECT_NE(index, 0);

    ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ndp_msg_ifindex_set(msg, index);
    ndp_msg_dest_set(msg, &dest);
    ndp_msg_target_set(msg, &target);
    ndp_msg_opt_set(msg);

    ret = ndp_msg_send(ndp, msg);
    EXPECT_EQ(ret, 0);

    ndp_msg_destroy(msg);
    ndp_close(ndp);
}

TEST(TestSendNdp, sendToFail)
{
    MOCKER(sendto).stubs().will(returnValue(-1));
    struct ndp *ndp;
    int index;
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;
    struct in6_addr target = IN6ADDR_ANY_INIT;
    struct in6_addr dest = IN6ADDR_ANY_INIT;
    errno = 1;

    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    index = get_if_index();
    EXPECT_NE(index, 0);

    ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ndp_msg_ifindex_set(msg, index);
    ndp_msg_dest_set(msg, &dest);
    ndp_msg_target_set(msg, &target);
    ndp_msg_opt_set(msg);

    ret = ndp_msg_send(ndp, msg);
    EXPECT_EQ(ret, -1);

    ndp_msg_destroy(msg);
    ndp_close(ndp);
    GlobalMockObject::verify();
}

TEST(TestSendNdp, sendToFailiForEINTR)
{
    MOCKER(sendto).stubs().will(returnValue(-1)).then(returnValue(0));
    struct ndp *ndp;
    int index;
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;
    struct in6_addr target = IN6ADDR_ANY_INIT;
    struct in6_addr dest = IN6ADDR_ANY_INIT;
    errno = 4;

    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    index = get_if_index();
    EXPECT_NE(index, 0);

    ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ndp_msg_ifindex_set(msg, index);
    ndp_msg_dest_set(msg, &dest);
    ndp_msg_target_set(msg, &target);
    ndp_msg_opt_set(msg);

    ret = ndp_msg_send(ndp, msg);
    EXPECT_EQ(ret, 0);

    ndp_msg_destroy(msg);
    ndp_close(ndp);
    GlobalMockObject::verify();
}

TEST(TestSendNdpWithFlag, msgTypeIsRs)
{
    struct ndp *ndp;
    int index;
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_RS;
    struct in6_addr target = IN6ADDR_ANY_INIT;
    struct in6_addr dest = IN6ADDR_ANY_INIT;
    uint8_t flags = ND_OPT_NORMAL;

    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    index = get_if_index();
    EXPECT_NE(index, 0);

    ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ndp_msg_ifindex_set(msg, index);
    ndp_msg_dest_set(msg, &dest);
    ndp_msg_target_set(msg, &target);
    ndp_msg_opt_set(msg);

    ret = ndp_msg_send_with_flags(ndp, msg, flags);
    EXPECT_EQ(ret, 0);

    ndp_msg_destroy(msg);
    ndp_close(ndp);
}

TEST(TestSendNdpWithFlag, msgTypeIsNs)
{
    struct ndp *ndp;
    int index;
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_NS;
    struct in6_addr target = IN6ADDR_ANY_INIT;
    struct in6_addr dest = IN6ADDR_ANY_INIT;
    uint8_t flags = ND_OPT_NORMAL;

    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    index = get_if_index();
    EXPECT_NE(index, 0);

    ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ndp_msg_ifindex_set(msg, index);
    ndp_msg_dest_set(msg, &dest);
    ndp_msg_target_set(msg, &target);
    ndp_msg_opt_set(msg);

    ret = ndp_msg_send_with_flags(ndp, msg, flags);
    EXPECT_EQ(ret, 0);

    ndp_msg_destroy(msg);
    ndp_close(ndp);
}

TEST(TestSendNdpWithFlag, msgTypeIsNa)
{
    struct ndp *ndp;
    int index;
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_NA;
    struct in6_addr target = IN6ADDR_ANY_INIT;
    struct in6_addr dest = IN6ADDR_ANY_INIT;
    uint8_t flags = ND_OPT_NORMAL;

    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    index = get_if_index();
    EXPECT_NE(index, 0);

    ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ndp_msg_ifindex_set(msg, index);
    ndp_msg_dest_set(msg, &dest);
    ndp_msg_target_set(msg, &target);
    ndp_msg_opt_set(msg);

    ret = ndp_msg_send_with_flags(ndp, msg, flags);
    EXPECT_EQ(ret, 0);

    ndp_msg_destroy(msg);
    ndp_close(ndp);
}

TEST(TestSendNdpWithFlag, msgTypeIsNaAndFlagIsNAUnsol)
{
    struct ndp *ndp;
    int index;
    struct ndp_msg *msg;
    enum ndp_msg_type msg_type = NDP_MSG_NA;
    struct in6_addr target = IN6ADDR_ANY_INIT;
    struct in6_addr dest = IN6ADDR_ANY_INIT;
    uint8_t flags = ND_OPT_NA_UNSOL;

    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    index = get_if_index();
    EXPECT_NE(index, 0);

    ret = ndp_msg_new(&msg, msg_type);
    EXPECT_EQ(ret, 0);

    ndp_msg_ifindex_set(msg, index);
    ndp_msg_dest_set(msg, &dest);
    ndp_msg_target_set(msg, &target);
    ndp_msg_opt_set(msg);

    ret = ndp_msg_send_with_flags(ndp, msg, flags);
    EXPECT_EQ(ret, 0);

    ndp_msg_destroy(msg);
    ndp_close(ndp);
}

TEST(TestRecvMsg, cmsgIsPKTINFO)
{
    struct msghdr msghdr;
    struct cmsghdr cmsghdr;
    msghdr.msg_control = &cmsghdr;
    msghdr.msg_controllen = sizeof(cmsghdr);
    cmsghdr.cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    cmsghdr.cmsg_level = IPPROTO_IPV6;
    cmsghdr.cmsg_type = IPV6_PKTINFO;
    MOCKER(recvmsg).stubs().with(any(), outBoundP(&msghdr, sizeof(msghdr)), any()).will(returnValue(1));
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    ret = ndp_call_eventfd_handler(ndp);
    EXPECT_EQ(ret, 0);

    ndp_close(ndp);
    GlobalMockObject::verify();
}

ssize_t my_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    struct cmsghdr *cmsghdr = nullptr;
    cmsghdr = (struct cmsghdr *)malloc(sizeof(struct cmsghdr) + sizeof(int));
    memset(cmsghdr, 0, sizeof(struct cmsghdr) + sizeof(int));
    msg->msg_control = cmsghdr;
    msg->msg_controllen = sizeof(struct cmsghdr) + sizeof(int);
    cmsghdr->cmsg_len = CMSG_LEN(sizeof(int));
    cmsghdr->cmsg_level = IPPROTO_IPV6;
    cmsghdr->cmsg_type = IPV6_HOPLIMIT;
    cmsghdr->__cmsg_data[0] = 255;

    ((char *)msg->msg_iov->iov_base)[0] = 135;

    return 128;
}

TEST(TestRecvMsg, cmsgIsHOPLIMIT)
{
    struct msghdr msghdr;
    MOCKER(recvmsg).stubs().will(invoke(my_recvmsg));
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    ret = ndp_call_eventfd_handler(ndp);
    EXPECT_EQ(ret, 0);

    ndp_close(ndp);
    GlobalMockObject::verify();
}

ssize_t my_recvmsg_level(int sockfd, struct msghdr *msg, int flags)
{
    struct cmsghdr *cmsghdr = nullptr;
    cmsghdr = (struct cmsghdr *)malloc(sizeof(struct cmsghdr) + sizeof(int));
    memset(cmsghdr, 0, sizeof(struct cmsghdr) + sizeof(int));
    msg->msg_control = cmsghdr;
    msg->msg_controllen = sizeof(struct cmsghdr) + sizeof(int);
    cmsghdr->cmsg_len = CMSG_LEN(sizeof(int));
    cmsghdr->cmsg_level = IPPROTO_ICMP;
    cmsghdr->cmsg_type = IPV6_HOPLIMIT;
    cmsghdr->__cmsg_data[0] = 255;

    ((char *)msg->msg_iov->iov_base)[0] = 135;

    return 128;
}

TEST(TestRecvMsg, msgLevelErr)
{
    struct msghdr msghdr;
    MOCKER(recvmsg).stubs().will(invoke(my_recvmsg_level));
    struct ndp *ndp;
    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    ret = ndp_call_eventfd_handler(ndp);
    EXPECT_EQ(ret, 0);

    ndp_close(ndp);
    GlobalMockObject::verify(); 
}

int msgrcv_handler_func1(struct ndp *ndp, struct ndp_msg *msg, void *priv)
{
    return 0;
}

int msgrcv_handler_func2(struct ndp *ndp, struct ndp_msg *msg, void *priv)
{
    return 0;
}

TEST(TestHandler, RegisterAndUnregister)
{
    struct ndp *ndp;
    int index;
    enum ndp_msg_type msg_type = NDP_MSG_NS;

    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    index = get_if_index();
    EXPECT_NE(index, 0);

    ret = ndp_msgrcv_handler_register(ndp, &msgrcv_handler_func1, msg_type, index, NULL);
    EXPECT_EQ(ret, 0);

    ret = ndp_msgrcv_handler_register(ndp, &msgrcv_handler_func2, msg_type, index, NULL);
    EXPECT_EQ(ret, 0);

    ndp_msgrcv_handler_unregister(ndp, &msgrcv_handler_func1, msg_type, index, NULL);
    ndp_msgrcv_handler_unregister(ndp, &msgrcv_handler_func2, msg_type, index, NULL);

    ndp_close(ndp);
}

TEST(TestHandler, RegisterExistFunc)
{
    struct ndp *ndp;
    int index;
    enum ndp_msg_type msg_type = NDP_MSG_NS;

    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    index = get_if_index();
    EXPECT_NE(index, 0);

    ret = ndp_msgrcv_handler_register(ndp, &msgrcv_handler_func1, msg_type, index, NULL);
    EXPECT_EQ(ret, 0);

    ret = ndp_msgrcv_handler_register(ndp, &msgrcv_handler_func1, msg_type, index, NULL);
    EXPECT_EQ(ret, -17);

    ndp_msgrcv_handler_unregister(ndp, &msgrcv_handler_func1, msg_type, index, NULL);

    ndp_close(ndp);
}

TEST(TestHandler, RegisterNullFunc)
{
    struct ndp *ndp;
    int index;
    enum ndp_msg_type msg_type = NDP_MSG_NS;

    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    index = get_if_index();
    EXPECT_NE(index, 0);

    ret = ndp_msgrcv_handler_register(ndp, NULL, msg_type, index, NULL);
    EXPECT_EQ(ret, -22);

    ndp_close(ndp);
}

TEST(TestHandler, RegisterMallocWrong)
{
    MOCKER(malloc).stubs().will(returnValue((void *)nullptr));
    struct ndp *ndp;
    int index;
    enum ndp_msg_type msg_type = NDP_MSG_NS;

    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    index = get_if_index();
    EXPECT_NE(index, 0);

    ret = ndp_msgrcv_handler_register(ndp, &msgrcv_handler_func1, msg_type, index, NULL);
    EXPECT_EQ(ret, -12);

    ndp_close(ndp);
    GlobalMockObject::verify();
}

TEST(TestHandler, UnregisterNotExistFunc)
{
    struct ndp *ndp;
    int index;
    enum ndp_msg_type msg_type = NDP_MSG_NS;

    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    index = get_if_index();
    EXPECT_NE(index, 0);

    ndp_msgrcv_handler_unregister(ndp, &msgrcv_handler_func1, msg_type, index, NULL);

    ndp_close(ndp);
}

TEST(TestHandler, UseRegisterFunc)
{
    struct msghdr msghdr;
    struct cmsghdr cmsghdr;
    msghdr.msg_control = &cmsghdr;
    msghdr.msg_controllen = sizeof(cmsghdr);
    cmsghdr.cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    cmsghdr.cmsg_level = IPPROTO_IPV6;
    cmsghdr.cmsg_type = IPV6_PKTINFO;
    MOCKER(recvmsg).stubs().with(any(), outBoundP(&msghdr, sizeof(msghdr)), any()).will(returnValue(1));
    struct ndp *ndp;
    int index;
    enum ndp_msg_type msg_type = NDP_MSG_NS;

    int ret = ndp_open(&ndp);
    EXPECT_EQ(ret, 0);

    index = get_if_index();
    EXPECT_NE(index, 0);

    ret = ndp_msgrcv_handler_register(ndp, &msgrcv_handler_func1, msg_type, index, NULL);
    EXPECT_EQ(ret, 0);

    ret = ndp_msgrcv_handler_register(ndp, &msgrcv_handler_func2, msg_type, index, NULL);
    EXPECT_EQ(ret, 0);

    ret = ndp_call_eventfd_handler(ndp);
    EXPECT_EQ(ret, 0);

    ndp_msgrcv_handler_unregister(ndp, &msgrcv_handler_func1, msg_type, index, NULL);
    ndp_msgrcv_handler_unregister(ndp, &msgrcv_handler_func2, msg_type, index, NULL);

    ndp_close(ndp);
    GlobalMockObject::verify();
}
