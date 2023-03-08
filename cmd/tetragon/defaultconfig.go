package main

const (
	// 监测http请求
	httpTracePoint = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: http
spec:
  tracepoints:
  - event: sys_enter_write
    args:
    - index: 5
      returnCopy: false
      type: fd
    - index: 6
      returnCopy: false
      sizeArgIndex: 8
      type: char_buf
    - index: 7
      returnCopy: false
      type: size_t
    selectors:
    - matchArgs:
      - index: 1
        operator: Prefix
        values:
        - HTTP
        - GET
        - POST
        - HEAD
        - PUT
        - DELETE
        - CONNECT
        - OPTIONS
        - TRACE
        - PATCH
    subsystem: syscalls
`
	// 监测dns请求
	dnsKprobe = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: dns
spec:
  kprobes:
  - args:
    - index: 0
      returnCopy: false
      type: sock
    - index: 2
      returnCopy: false
      type: size_t
    call: udp_sendmsg
    return: false
    syscall: false
  - args:
    - index: 0
      returnCopy: false
      type: sock
    - index: 2
      returnCopy: false
      type: size_t
    call: udp_recvmsg
    return: false
    syscall: false
`
	// 监控tcp连接
	tcpKprobe = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: tcp-connect
spec:
  kprobes:
    - args:
        - index: 0
          returnCopy: false
          type: sock
      call: tcp_connect
      return: false
      syscall: false
    - args:
        - index: 0
          returnCopy: false
          type: sock
      call: tcp_close
      return: false
      syscall: false
    - args:
        - index: 0
          returnCopy: false
          type: sock
        - index: 1
          returnCopy: false
          type: string
        - index: 2
          returnCopy: false
          type: int
      call: tcp_sendmsg
      return: false
      syscall: false
    - args:
        - index: 0
          returnCopy: false
          type: sock
        - index: 1
          returnCopy: false
          type: string
        - index: 2
          returnCopy: false
          type: int
        - index: 4
          returnCopy: false
          type: int
      call: tcp_recvmsg
      return: false
      syscall: false
    - call: "tcp_retransmit_skb" # 重传
      syscall: false
      args:
        - index: 0
          type: "sock"
        - index: 1
          type: "skb"
    - call: "tcp_time_wait"
      syscall: false
      args:
        - index: 0
          type: "sock"
        - index: 1
          type: "int"
`

	// 监控 tcp 连接状态 { 1, "TCP_ESTABLISHED" }, { 2, "TCP_SYN_SENT" }, { 3, "TCP_SYN_RECV" }, { 4, "TCP_FIN_WAIT1" }, { 5, "TCP_FIN_WAIT2" }, { 6, "TCP_TIME_WAIT" }, { 7, "TCP_CLOSE" }, { 8, "TCP_CLOSE_WAIT" }, { 9, "TCP_LAST_ACK" }, { 10, "TCP_LISTEN" }, { 11, "TCP_CLOSING" }, { 12, "TCP_NEW_SYN_RECV" }
	tcpTracePoint = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: tcp-state
spec:
  tracepoints:
    - event: inet_sock_set_state
      subsystem: sock
      args:
        - index: 5  # old state
          type: "int"
        - index: 6  # new state
          type: "int"
        - index: 11  # saddr4
          type: "int"
        - index: 12  # daddr4
          type: "int"
      selectors:
        - matchArgs:
            - index: 1
              operator: Equal
              values:
                - "8"
    - event: inet_sock_set_state
      subsystem: sock
      args:
        - index: 5  # old state
          type: "int"
        - index: 6  # new state
          type: "int"
        - index: 11  # saddr4
          type: "int"
        - index: 12  # daddr4
          type: "int"
      selectors:
        - matchArgs:
            - index: 0
              operator: Equal
              values:
                - "8"
`
)

var defaultTracingPolicies = []string{
	httpTracePoint,
	dnsKprobe,
	tcpKprobe,
	tcpTracePoint,
}

const (
	defaultProcFS           = "/procRoot"
	defaultProcessCacheSize = 6553600
	defaultLogLevel         = "error"
	defaultEnableK8sAPI     = false
	defaultMetricsServer    = ":2112"
	defaultGopsAddr         = "localhost:8118"
	defaultEventQueueSize   = 100000
	defaultRBSize           = 268435456
	defaultPprofAddr        = ""
)
