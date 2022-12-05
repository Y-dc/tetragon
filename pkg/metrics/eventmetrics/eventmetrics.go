// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventmetrics

import (
	"bufio"
	"bytes"
	"net/http"
	"regexp"
	"strings"

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

const (
	tracePointEnterWrite = "sys_enter_write"
	tracePointEnterRead  = "sys_enter_read"
)

var (
	methodReg       = regexp.MustCompile("^(GET)|(POST)|(HEAD)|(PUT)|(DELETE)|(CONNECT)|(OPTIONS)|(TRACE)|(PATCH)$")
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
	TracePointHttpResponseRequest = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "tracepoint_http_response_request_total",
		Help:        "The total number of HTTP response request total.",
		ConstLabels: nil,
	}, []string{"namespace", "pod", "binary", "proto", "host", "method", "uri"})
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
	scanner := bufio.NewScanner(bytes.NewReader(value))
	if !scanner.Scan() {
		return
	}
	proto, status, ok := strings.Cut(scanner.Text(), " ")
	if !ok {
		return
	}
	if _, _, ok = http.ParseHTTPVersion(proto); !ok {
		return
	}

	statusCode, _, _ := strings.Cut(strings.TrimLeft(status, " "), " ")
	if len(statusCode) != 3 {
		return
	}

	TracePointHttpResponse.WithLabelValues(namespace, pod, binary, statusCode).Inc()
}

func parseRequestMessage(value []byte, event, namespace, pod, binary string) {
	// try to parse the buf as http request
	scanner := bufio.NewScanner(bytes.NewReader(value))
	if !scanner.Scan() {
		return
	}
	method, rest, ok1 := strings.Cut(scanner.Text(), " ")
	if !ok1 || !methodReg.MatchString(method) {
		return
	}
	requestURI, proto, ok2 := strings.Cut(rest, " ")
	if !ok2 {
		return
	}
	if !scanner.Scan() {
		return
	}
	_, host, ok3 := strings.Cut(scanner.Text(), ": ")
	if !ok3 {
		return
	}

	switch event {
	case tracePointEnterWrite:
		TracePointHttpRequest.WithLabelValues(
			namespace, pod, binary, proto, host, method, requestURI).Inc()
	case tracePointEnterRead:
		TracePointHttpResponseRequest.WithLabelValues(
			namespace, pod, binary, proto, host, method, requestURI).Inc()
	}
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
	switch event {
	case "sys_enter_write":
		for _, arg := range args {
			data := arg.GetBytesArg()
			if len(data) > 0 {
				//fmt.Printf("DCY log:\n binary: %s \n event: %s\n, args: %s\n\n",
				//	binary, event, data)
				parseResponseMessage(data, namespace, pod, binary)
				parseRequestMessage(data, event, namespace, pod, binary)
			}
		}
	case "sys_enter_read":
		for _, arg := range args {
			data := arg.GetBytesArg()
			if len(data) > 0 {
				//fmt.Printf("DCY log:\n binary: %s \n event: %s\n, args: %s\n\n",
				//	binary, event, data)
				parseRequestMessage(data, event, namespace, pod, binary)
			}
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
