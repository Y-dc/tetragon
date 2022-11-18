// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventmetrics

import (
	"bufio"
	"bytes"
	"net/http"
	"strconv"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/reader/exec"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	EventsProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "events_total",
		Help:        "The total number of Tetragon events",
		ConstLabels: nil,
	}, []string{"type", "namespace", "pod", "binary"})
	FlagCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "flags_total",
		Help:        "The total number of Tetragon flags. For internal use only.",
		ConstLabels: nil,
	}, []string{"type"})
	NotifyOverflowedEvents = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "notify_overflowed_events",
		Help:        "The total number of events dropped because listener buffer was full",
		ConstLabels: nil,
	}, nil)
	KprobeEventsProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "events_kprobe_total",
		Help:        "The total number of Tetragon event type process_kprobe.",
		ConstLabels: nil,
	}, []string{"namespace", "pod", "binary", "function"})
	TracePointHttpResponse = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "tracepoint_http_response_total",
		Help:        "The total number of HTTP response total.",
		ConstLabels: nil,
	}, []string{"namespace", "pod", "binary", "status"})
	TracePointHttpRequest = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "tracepoint_http_request_total",
		Help:        "The total number of HTTP request total.",
		ConstLabels: nil,
	}, []string{"namespace", "pod", "binary", "proto", "host", "method", "uri"})
)

func GetProcessInfo(process *tetragon.Process) (binary, pod, namespace string) {
	if process != nil {
		binary = process.Binary
		if process.Pod != nil {
			namespace = process.Pod.Namespace
			pod = process.Pod.Name
		}
	} else {
		errormetrics.ErrorTotalInc(errormetrics.EventMissingProcessInfo)
	}
	return binary, pod, namespace
}

func parseResponseMessage(value []byte, namespace, pod, binary string) {
	// try to parse the buf as http response
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(value)), nil)
	if err != nil {
		//fmt.Printf("Failed to parse Response, %s\n", err)
		return
	}

	//body := resp.Body
	//b, _ := ioutil.ReadAll(body)
	//body.Close()
	//fmt.Printf("\nStatusCode: %s, Len: %s, ContentType: %s, Body: %s\n",
	//	color.GreenString("%d", resp.StatusCode),
	//	color.GreenString("%d", resp.ContentLength),
	//	color.GreenString("%s", resp.Header["Content-Type"]),
	//	color.GreenString("%s", string(b)))
	TracePointHttpResponse.WithLabelValues(namespace, pod, binary, strconv.Itoa(resp.StatusCode)).Inc()
}

func parseRequestMessage(value []byte, namespace, pod, binary string) {
	// try to parse the buf as http request
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(value)))
	if err != nil {
		//fmt.Printf("Failed to parse Request, %s\n", err)
		return
	}

	//fmt.Printf("\nProtocol: %s, Method: %s, URI: %s, Host: %s\n",
	//	color.GreenString("%s", req.Proto),
	//	color.GreenString("%s", req.Method),
	//	color.GreenString("%s", req.RequestURI),
	//	color.GreenString("%s", req.Host))
	TracePointHttpRequest.WithLabelValues(
		namespace, pod, binary, req.Proto, req.Host, req.Method, req.RequestURI).Inc()
}

func handleOriginalEvent(originalEvent interface{}) {
	var flags uint32
	switch msg := originalEvent.(type) {
	case *processapi.MsgExecveEventUnix:
		flags = msg.Process.Flags
	}
	for _, flag := range exec.DecodeCommonFlags(flags) {
		FlagCount.WithLabelValues(flag).Inc()
	}
}

func handleProcessedEvent(processedEvent interface{}) {
	var eventType, namespace, pod, binary string
	switch ev := processedEvent.(type) {
	case *tetragon.GetEventsResponse:
		binary, pod, namespace = GetProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
		var err error
		eventType, err = helpers.ResponseTypeString(ev)
		if err != nil {
			logger.GetLogger().WithField("event", processedEvent).WithError(err).Warn("metrics: handleProcessedEvent: unhandled event")
			eventType = "unhandled"
		}
		handleTracePointToHTTP(ev, eventType, namespace, pod, binary)
		handleProcessedKprobeEvent(ev, eventType, namespace, pod, binary)
	default:
		eventType = "unknown"
	}
	EventsProcessed.WithLabelValues(eventType, namespace, pod, binary).Inc()
}

func handleTracePointToHTTP(ev *tetragon.GetEventsResponse, eventType, namespace, pod, binary string) {
	if eventType != tetragon.EventType_PROCESS_TRACEPOINT.String() {
		return
	}
	_, event, args := helpers.ResponseGetTracePointInfo(ev)
	if event != "sys_enter_write" && event != "sys_enter_read" {
		return
	}
	for _, arg := range args {
		data := arg.GetBytesArg()
		if len(data) > 0 {
			//fmt.Printf("DCY log:\n binary: %s \n event: %s\n, args: %s\n\n",
			//	binary, event, data)
			parseResponseMessage(data, namespace, pod, binary)
			parseRequestMessage(data, namespace, pod, binary)
		}
	}
}

// handleProcessedKprobeEvent handles process_kprobe events metrics(KprobeEventsProcessed)
func handleProcessedKprobeEvent(ev *tetragon.GetEventsResponse, eventType, namespace, pod, binary string) {
	if eventType != tetragon.EventType_PROCESS_KPROBE.String() {
		return
	}
	funcName, _ := helpers.ResponseGetFunctionInfo(ev)
	KprobeEventsProcessed.WithLabelValues(namespace, pod, binary, funcName).Inc()
}

func ProcessEvent(originalEvent interface{}, processedEvent interface{}) {
	handleOriginalEvent(originalEvent)
	handleProcessedEvent(processedEvent)
}
