// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventmetrics

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/reader/exec"
	"github.com/fatih/color"
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
	HttpResponse = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "http_response_total",
		Help:        "The total number of HTTP response total.",
		ConstLabels: nil,
	}, []string{"method", "status"})
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
		if eventType == tetragon.EventType_PROCESS_TRACEPOINT.String() {
			_, event, args := helpers.ResponseGetTracePointInfo(ev)
			if (event == "sys_enter_write" || event == "sys_enter_read") && binary == "/app/call" {
				for _, arg := range args {
					data := arg.GetBytesArg()
					if len(data) > 0 {
						fmt.Printf("DCY log:\n binary: %s \n event: %s\n, args: %s\n\n",
							binary, event, data)
						parseResponseMessage(data)
						parseRequestMessage(data)
					}
				}
			}
		}
	default:
		eventType = "unknown"
	}
	EventsProcessed.WithLabelValues(eventType, namespace, pod, binary).Inc()

}

func parseResponseMessage(value []byte) {
	// We have the complete request so we try to parse the actual HTTP request.
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(value)), nil)
	if err != nil {
		fmt.Printf("Failed to parse %s to Response, %s\n", value, err)
		return
	}

	body := resp.Body
	b, _ := ioutil.ReadAll(body)
	body.Close()
	fmt.Printf("\nStatusCode: %s, Len: %s, ContentType: %s, Body: %s\n",
		color.GreenString("%d", resp.StatusCode),
		color.GreenString("%d", resp.ContentLength),
		color.GreenString("%s", resp.Header["Content-Type"]),
		color.GreenString("%s", string(b)))
}

func parseRequestMessage(value []byte) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(value)))
	if err != nil {
		fmt.Printf("Failed to parse %s to Request, %s\n", value, err)
		return
	}

	body := req.Body
	b, _ := ioutil.ReadAll(body)
	body.Close()
	fmt.Printf("\nMethod: %s, URI: %s, ContentType: %s, Body: %s\n",
		color.GreenString("%s", req.Method),
		color.GreenString("%s", req.RequestURI),
		color.GreenString("%s", req.Host),
		color.GreenString("%s", string(b)))
}

// handleProcessedKprobeEvent handles process_kprobe events metrics(KprobeEventsProcessed)
func handleProcessedKprobeEvent(processedEvent interface{}) {
	var eventType, namespace, pod, binary, funcName string
	switch ev := processedEvent.(type) {
	case *tetragon.GetEventsResponse:
		binary, pod, namespace = GetProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
		var err error
		eventType, err = helpers.ResponseTypeString(ev)
		if err != nil {
			logger.GetLogger().WithField("event", processedEvent).WithError(err).Warn("metrics: handleProcessedEvent: unhandled event")
			eventType = "unhandled"
		}
		if eventType != tetragon.EventType_PROCESS_KPROBE.String() {
			return
		}
		funcName, _ = helpers.ResponseGetFunctionInfo(ev)
	default:
		return
	}

	KprobeEventsProcessed.WithLabelValues(namespace, pod, binary, funcName).Inc()
}

func ProcessEvent(originalEvent interface{}, processedEvent interface{}) {
	handleOriginalEvent(originalEvent)
	handleProcessedEvent(processedEvent)
	handleProcessedKprobeEvent(processedEvent)
}

func ProcessHttpResponse(method, status string) {
	HttpResponse.WithLabelValues(method, status).Inc()
}
