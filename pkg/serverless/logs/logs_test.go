// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package logs

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/aggregator"
	"github.com/DataDog/datadog-agent/pkg/logs/config"
	"github.com/DataDog/datadog-agent/pkg/logs/scheduler"
	"github.com/DataDog/datadog-agent/pkg/logs/service"
	"github.com/DataDog/datadog-agent/pkg/serverless/executioncontext"
	serverlessMetrics "github.com/DataDog/datadog-agent/pkg/serverless/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalExtensionLog(t *testing.T) {
	raw, err := ioutil.ReadFile("./testdata/extension_log.json")
	require.NoError(t, err)
	var messages []logMessage
	err = json.Unmarshal(raw, &messages)
	require.NoError(t, err)

	expectedTime, _ := time.Parse(logMessageTimeLayout, "2020-08-20T12:31:32.123Z")
	expectedLogMessage := logMessage{
		logType:      logTypeExtension,
		time:         expectedTime,
		stringRecord: "sample extension log",
	}
	assert.Equal(t, expectedLogMessage, messages[0])
}

func TestShouldProcessLog(t *testing.T) {

	validLog := logMessage{
		logType: logTypePlatformReport,
	}

	invalidLog0 := logMessage{
		logType: logTypePlatformLogsSubscription,
	}

	invalidLog1 := logMessage{
		logType: logTypePlatformExtension,
	}

	nonEmptyARN := "arn:aws:lambda:us-east-1:123456789012:function:my-function"
	emptyARN := ""

	nonEmptyRequestID := "8286a188-ba32-4475-8077-530cd35c09a9"
	emptyRequestID := ""

	assert.True(t, shouldProcessLog(&executioncontext.ExecutionContext{ARN: nonEmptyARN, LastRequestID: nonEmptyRequestID}, validLog))
	assert.False(t, shouldProcessLog(&executioncontext.ExecutionContext{ARN: emptyARN, LastRequestID: emptyRequestID}, validLog))
	assert.False(t, shouldProcessLog(&executioncontext.ExecutionContext{ARN: nonEmptyARN, LastRequestID: emptyRequestID}, validLog))
	assert.False(t, shouldProcessLog(&executioncontext.ExecutionContext{ARN: emptyARN, LastRequestID: nonEmptyRequestID}, validLog))

	assert.False(t, shouldProcessLog(&executioncontext.ExecutionContext{ARN: nonEmptyARN, LastRequestID: nonEmptyRequestID}, invalidLog0))
	assert.False(t, shouldProcessLog(&executioncontext.ExecutionContext{ARN: emptyARN, LastRequestID: emptyRequestID}, invalidLog0))
	assert.False(t, shouldProcessLog(&executioncontext.ExecutionContext{ARN: nonEmptyARN, LastRequestID: emptyRequestID}, invalidLog0))
	assert.False(t, shouldProcessLog(&executioncontext.ExecutionContext{ARN: emptyARN, LastRequestID: nonEmptyRequestID}, invalidLog0))

	assert.False(t, shouldProcessLog(&executioncontext.ExecutionContext{ARN: nonEmptyARN, LastRequestID: nonEmptyRequestID}, invalidLog1))
	assert.False(t, shouldProcessLog(&executioncontext.ExecutionContext{ARN: emptyARN, LastRequestID: emptyRequestID}, invalidLog1))
	assert.False(t, shouldProcessLog(&executioncontext.ExecutionContext{ARN: nonEmptyARN, LastRequestID: emptyRequestID}, invalidLog1))
	assert.False(t, shouldProcessLog(&executioncontext.ExecutionContext{ARN: emptyARN, LastRequestID: nonEmptyRequestID}, invalidLog1))
}

func TestCreateStringRecordForReportLogWithInitDuration(t *testing.T) {
	var sampleLogMessage = logMessage{
		objectRecord: platformObjectRecord{
			requestID: "cf84ebaf-606a-4b0f-b99b-3685bfe973d7",
			reportLogItem: reportLogMetrics{
				durationMs:       100.00,
				billedDurationMs: 100,
				memorySizeMB:     128,
				maxMemoryUsedMB:  128,
				initDurationMs:   50.00,
			},
		},
	}
	output := createStringRecordForReportLog(&sampleLogMessage)
	expectedOutput := "REPORT RequestId: cf84ebaf-606a-4b0f-b99b-3685bfe973d7\tDuration: 100.00 ms\tBilled Duration: 100 ms\tMemory Size: 128 MB\tMax Memory Used: 128 MB\tInit Duration: 50.00 ms"
	assert.Equal(t, expectedOutput, output)
}

func TestCreateStringRecordForReportLogWithoutInitDuration(t *testing.T) {
	var sampleLogMessage = logMessage{
		objectRecord: platformObjectRecord{
			requestID: "cf84ebaf-606a-4b0f-b99b-3685bfe973d7",
			reportLogItem: reportLogMetrics{
				durationMs:       100.00,
				billedDurationMs: 100,
				memorySizeMB:     128,
				maxMemoryUsedMB:  128,
				initDurationMs:   0.00,
			},
		},
	}
	output := createStringRecordForReportLog(&sampleLogMessage)
	expectedOutput := "REPORT RequestId: cf84ebaf-606a-4b0f-b99b-3685bfe973d7\tDuration: 100.00 ms\tBilled Duration: 100 ms\tMemory Size: 128 MB\tMax Memory Used: 128 MB"
	assert.Equal(t, expectedOutput, output)
}

func TestRemoveInvalidTracingItemWellFormatted(t *testing.T) {
	raw, err := ioutil.ReadFile("./testdata/valid_logs_payload.json")
	require.NoError(t, err)
	sanitizedData := removeInvalidTracingItem(raw)
	assert.Equal(t, raw, sanitizedData)
}

func TestRemoveInvalidTracingItemNotWellFormatted(t *testing.T) {
	raw, err := ioutil.ReadFile("./testdata/invalid_logs_payload.json")
	require.NoError(t, err)
	sanitizedData := removeInvalidTracingItem(raw)
	sanitizedRaw, sanitizedErr := ioutil.ReadFile("./testdata/invalid_logs_payload_sanitized.json")
	require.NoError(t, sanitizedErr)
	assert.Equal(t, string(sanitizedRaw), string(sanitizedData))
}

func TestParseLogsAPIPayloadWellFormated(t *testing.T) {
	raw, err := ioutil.ReadFile("./testdata/valid_logs_payload.json")
	require.NoError(t, err)
	messages, err := parseLogsAPIPayload(raw)
	assert.Nil(t, err)
	assert.NotNil(t, messages)
	assert.NotNil(t, messages[0].objectRecord.requestID)
}

func TestParseLogsAPIPayloadNotWellFormated(t *testing.T) {
	raw, err := ioutil.ReadFile("./testdata/invalid_logs_payload.json")
	require.NoError(t, err)
	messages, err := parseLogsAPIPayload(raw)
	assert.Nil(t, err)
	assert.NotNil(t, messages[0].objectRecord.requestID)
}

func TestParseLogsAPIPayloadNotWellFormatedButNotRecoverable(t *testing.T) {
	raw, err := ioutil.ReadFile("./testdata/invalid_logs_payload_unrecoverable.json")
	require.NoError(t, err)
	_, err = parseLogsAPIPayload(raw)
	assert.NotNil(t, err)
}

func TestGetLambdaSourceNilScheduler(t *testing.T) {
	assert.Nil(t, GetLambdaSource())
}

func TestGetLambdaSourceNilSource(t *testing.T) {
	logSources := config.NewLogSources()
	services := service.NewServices()
	scheduler.CreateScheduler(logSources, services)
	assert.Nil(t, GetLambdaSource())
}

func TestGetLambdaSourceValidSource(t *testing.T) {
	logSources := config.NewLogSources()
	chanSource := config.NewLogSource("TestLog", &config.LogsConfig{
		Type:    config.StringChannelType,
		Source:  "lambda",
		Tags:    nil,
		Channel: nil,
	})
	logSources.AddSource(chanSource)
	services := service.NewServices()
	scheduler.CreateScheduler(logSources, services)
	assert.NotNil(t, GetLambdaSource())
}

func TestProcessMessageValid(t *testing.T) {
	demux := aggregator.InitTestAgentDemultiplexerWithFlushInterval(time.Hour)
	defer demux.Stop(false)

	message := logMessage{
		logType: logTypePlatformReport,
		time:    time.Now(),
		objectRecord: platformObjectRecord{
			reportLogItem: reportLogMetrics{
				durationMs:       1000.0,
				billedDurationMs: 800.0,
				memorySizeMB:     1024.0,
				maxMemoryUsedMB:  256.0,
				initDurationMs:   100.0,
			},
		},
	}
	arn := "arn:aws:lambda:us-east-1:123456789012:function:test-function"
	lastRequestID := "8286a188-ba32-4475-8077-530cd35c09a9"
	metricTags := []string{"functionname:test-function"}

	computeEnhancedMetrics := true
	mockGetExecutionContext := func() executioncontext.ExecutionContext {
		return executioncontext.ExecutionContext{
			ARN:           arn,
			LastRequestID: lastRequestID,
		}
	}
	mockUpdateExecutionContext := func(string, time.Time) {}
	go processMessage(message, mockGetExecutionContext, mockUpdateExecutionContext, computeEnhancedMetrics, metricTags, demux, func() {})

	received := demux.WaitForSamples(100 * time.Millisecond)
	assert.Equal(t, len(received), 6)
	demux.Reset()

	computeEnhancedMetrics = false
	go processMessage(message, mockGetExecutionContext, mockUpdateExecutionContext, computeEnhancedMetrics, metricTags, demux, func() {})

	received = demux.WaitForSamples(100 * time.Millisecond)
	assert.Equal(t, len(received), 0, "we should NOT have received metrics")
}

func TestProcessMessageStartValid(t *testing.T) {
	demux := aggregator.InitTestAgentDemultiplexerWithFlushInterval(time.Hour)
	defer demux.Stop(false)

	message := logMessage{
		logType: logTypePlatformStart,
		time:    time.Now(),
		objectRecord: platformObjectRecord{
			requestID: "8286a188-ba32-4475-8077-530cd35c09a9",
		},
	}
	arn := "arn:aws:lambda:us-east-1:123456789012:function:test-function"
	lastRequestID := "8286a188-ba32-4475-8077-530cd35c09a9"
	metricTags := []string{"functionname:test-function"}

	mockExecutionContext := executioncontext.ExecutionContext{
		ARN:           arn,
		LastRequestID: lastRequestID,
	}
	mockGetExecutionContext := func() executioncontext.ExecutionContext {
		return mockExecutionContext
	}
	mockUpdateExecutionContext := func(lastRequestID string, time time.Time) {
		mockExecutionContext.LastLogRequestID = lastRequestID
	}

	computeEnhancedMetrics := true

	runtimeDoneCallbackWasCalled := false
	mockRuntimeDone := func() {
		runtimeDoneCallbackWasCalled = true
	}

	processMessage(message, mockGetExecutionContext, mockUpdateExecutionContext, computeEnhancedMetrics, metricTags, demux, mockRuntimeDone)
	assert.Equal(t, lastRequestID, mockExecutionContext.LastLogRequestID)
	assert.Equal(t, runtimeDoneCallbackWasCalled, false)
}

func TestProcessMessagePlatformRuntimeDoneValid(t *testing.T) {
	demux := aggregator.InitTestAgentDemultiplexerWithFlushInterval(time.Hour)
	defer demux.Stop(false)
	message := logMessage{
		logType: logTypePlatformRuntimeDone,
		time:    time.Now(),
		objectRecord: platformObjectRecord{
			requestID: "8286a188-ba32-4475-8077-530cd35c09a9",
			runtimeDoneItem: runtimeDoneItem{
				status: "success",
			},
		},
	}
	arn := "arn:aws:lambda:us-east-1:123456789012:function:test-function"
	lastRequestID := "8286a188-ba32-4475-8077-530cd35c09a9"
	metricTags := []string{"functionname:test-function"}
	startTime := time.Date(2020, 01, 01, 01, 01, 01, 500000000, time.UTC)
	computeEnhancedMetrics := true

	mockExecutionContext := executioncontext.ExecutionContext{
		ARN:           arn,
		LastRequestID: lastRequestID,
		StartTime:     startTime,
	}
	mockGetExecutionContext := func() executioncontext.ExecutionContext {
		return mockExecutionContext
	}
	mockUpdateExecutionContext := func(string, time.Time) {
		// do nothing
	}

	runtimeDoneCallbackWasCalled := false
	mockRuntimeDone := func() {
		runtimeDoneCallbackWasCalled = true
	}

	processMessage(message, mockGetExecutionContext, mockUpdateExecutionContext, computeEnhancedMetrics, metricTags, demux, mockRuntimeDone)
	assert.Equal(t, startTime, mockExecutionContext.StartTime)
	assert.Equal(t, runtimeDoneCallbackWasCalled, true)
}

func TestProcessMessagePlatformRuntimeDonePreviousInvocation(t *testing.T) {
	demux := aggregator.InitTestAgentDemultiplexerWithFlushInterval(time.Hour)
	defer demux.Stop(false)

	previousRequestID := "9397b299-cb43-5586-9188-641de46d10b0"
	currentRequestID := "8286a188-ba32-4475-8077-530cd35c09a9"
	message := logMessage{
		logType: logTypePlatformRuntimeDone,
		time:    time.Now(),
		objectRecord: platformObjectRecord{
			requestID: previousRequestID,
			runtimeDoneItem: runtimeDoneItem{
				status: "success",
			},
		},
	}
	arn := "arn:aws:lambda:us-east-1:123456789012:function:test-function"
	lastRequestID := currentRequestID
	metricTags := []string{"functionname:test-function"}

	startTime := time.Date(2020, 01, 01, 01, 01, 01, 500000000, time.UTC)
	executionContext := &executioncontext.ExecutionContext{ARN: arn, LastRequestID: lastRequestID, StartTime: startTime}
	computeEnhancedMetrics := true

	mockExecutionContext := executioncontext.ExecutionContext{
		ARN:           arn,
		LastRequestID: lastRequestID,
		StartTime:     startTime,
	}
	mockGetExecutionContext := func() executioncontext.ExecutionContext {
		return mockExecutionContext
	}
	mockUpdateExecutionContext := func(string, time.Time) {
		// do nothing
	}

	runtimeDoneCallbackWasCalled := false
	mockRuntimeDone := func() {
		runtimeDoneCallbackWasCalled = true
	}

	processMessage(message, mockGetExecutionContext, mockUpdateExecutionContext, computeEnhancedMetrics, metricTags, demux, mockRuntimeDone)
	assert.Equal(t, startTime, executionContext.StartTime)
	// Runtime done callback should NOT be called if the log message was for a previous invocation
	assert.Equal(t, runtimeDoneCallbackWasCalled, false)
}

func TestProcessMessageShouldNotProcessArnNotSet(t *testing.T) {
	demux := aggregator.InitTestAgentDemultiplexerWithFlushInterval(time.Hour)
	defer demux.Stop(false)
	message := logMessage{
		logType: logTypePlatformReport,
		time:    time.Now(),
		objectRecord: platformObjectRecord{
			reportLogItem: reportLogMetrics{
				durationMs:       1000.0,
				billedDurationMs: 800.0,
				memorySizeMB:     1024.0,
				maxMemoryUsedMB:  256.0,
				initDurationMs:   100.0,
			},
		},
	}

	metricTags := []string{"functionname:test-function"}

	mockExecutionContext := executioncontext.ExecutionContext{
		ARN:           "",
		LastRequestID: "",
	}
	mockGetExecutionContext := func() executioncontext.ExecutionContext {
		return mockExecutionContext
	}
	mockUpdateExecutionContext := func(string, time.Time) {
		// do nothing
	}

	computeEnhancedMetrics := true
	go processMessage(message, mockGetExecutionContext, mockUpdateExecutionContext, computeEnhancedMetrics, metricTags, demux, func() {})

	received := demux.WaitForSamples(100 * time.Millisecond)
	assert.Equal(t, len(received), 0, "We should NOT have received metrics")
}

func TestProcessMessageShouldNotProcessLogsDropped(t *testing.T) {
	demux := aggregator.InitTestAgentDemultiplexerWithFlushInterval(time.Hour)
	defer demux.Stop(false)
	message := logMessage{
		logType:      logTypePlatformLogsDropped,
		time:         time.Now(),
		stringRecord: "bla bla bla",
	}

	arn := "arn:aws:lambda:us-east-1:123456789012:function:test-function"
	lastRequestID := "8286a188-ba32-4475-8077-530cd35c09a9"
	metricTags := []string{"functionname:test-function"}
	computeEnhancedMetrics := true

	mockExecutionContext := executioncontext.ExecutionContext{
		ARN:           arn,
		LastRequestID: lastRequestID,
	}
	mockGetExecutionContext := func() executioncontext.ExecutionContext {
		return mockExecutionContext
	}
	mockUpdateExecutionContext := func(string, time.Time) {
		// do nothing
	}

	go processMessage(message, mockGetExecutionContext, mockUpdateExecutionContext, computeEnhancedMetrics, metricTags, demux, func() {})

	received := demux.WaitForSamples(100 * time.Millisecond)
	assert.Equal(t, len(received), 0, "We should NOT have received metrics")
}

func TestProcessMessageShouldProcessLogTypeFunction(t *testing.T) {
	demux := aggregator.InitTestAgentDemultiplexerWithFlushInterval(time.Hour)
	defer demux.Stop(false)
	message := logMessage{
		logType:      logTypeFunction,
		time:         time.Now(),
		stringRecord: "fatal error: runtime: out of memory",
	}

	arn := "arn:aws:lambda:us-east-1:123456789012:function:test-function"
	lastRequestID := "8286a188-ba32-4475-8077-530cd35c09a9"
	metricTags := []string{"functionname:test-function"}
	computeEnhancedMetrics := true

	mockExecutionContext := executioncontext.ExecutionContext{
		ARN:           arn,
		LastRequestID: lastRequestID,
	}
	mockGetExecutionContext := func() executioncontext.ExecutionContext {
		return mockExecutionContext
	}
	mockUpdateExecutionContext := func(string, time.Time) {
		// do nothing
	}

	go processMessage(message, mockGetExecutionContext, mockUpdateExecutionContext, computeEnhancedMetrics, metricTags, demux, func() {})

	received := demux.WaitForSamples(100 * time.Millisecond)
	assert.Equal(t, len(received), 2)
	assert.Equal(t, serverlessMetrics.OutOfMemoryMetric, received[0].Name)
	assert.Equal(t, serverlessMetrics.ErrorsMetric, received[1].Name)
}

func TestProcessLogMessageLogsEnabled(t *testing.T) {

	logChannel := make(chan *config.ChannelMessage)

	mockExecutionContext := executioncontext.ExecutionContext{
		ARN:           "myARN",
		LastRequestID: "myRequestID",
	}
	mockGetExecutionContext := func() executioncontext.ExecutionContext {
		return mockExecutionContext
	}
	mockUpdateExecutionContext := func(string, time.Time) {
		// do nothing
	}

	logCollection := &LambdaLogsCollector{
		LogsEnabled: true,
		LogChannel:  logChannel,
		ExtraTags: &Tags{
			Tags: []string{"tag0:value0,tag1:value1"},
		},
		GetExecutionContext:                mockGetExecutionContext,
		UpdateExecutionContextFromStartLog: mockUpdateExecutionContext,
	}

	logMessages := []logMessage{
		{
			stringRecord: "hi, log 0",
		},
		{
			stringRecord: "hi, log 1",
		},
		{
			stringRecord: "hi, log 2",
		},
	}
	go processLogMessages(logCollection, logMessages)

	select {
	case received := <-logChannel:
		assert.NotNil(t, received)
		assert.Equal(t, "myARN", received.Lambda.ARN)
		assert.Equal(t, "myRequestID", received.Lambda.RequestID)
	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "We should have received logs")
	}
}

func TestProcessLogMessageNoStringRecordPlatformLog(t *testing.T) {

	logChannel := make(chan *config.ChannelMessage)

	mockExecutionContext := executioncontext.ExecutionContext{
		ARN:           "myARN",
		LastRequestID: "myRequestID",
	}
	mockGetExecutionContext := func() executioncontext.ExecutionContext {
		return mockExecutionContext
	}
	mockUpdateExecutionContext := func(string, time.Time) {
		// do nothing
	}

	logCollection := &LambdaLogsCollector{
		LogsEnabled: true,
		LogChannel:  logChannel,
		ExtraTags: &Tags{
			Tags: []string{"tag0:value0,tag1:value1"},
		},
		GetExecutionContext:                mockGetExecutionContext,
		UpdateExecutionContextFromStartLog: mockUpdateExecutionContext,
	}

	logMessages := []logMessage{
		{
			logType: logTypePlatformRuntimeDone,
		},
	}
	go processLogMessages(logCollection, logMessages)

	select {
	case <-logChannel:
		assert.Fail(t, "We should not have received logs")
	case <-time.After(100 * time.Millisecond):
		// nothing to do here
	}
}

func TestProcessLogMessageNoStringRecordFunctionLog(t *testing.T) {

	logChannel := make(chan *config.ChannelMessage)

	mockExecutionContext := executioncontext.ExecutionContext{
		ARN:           "myARN",
		LastRequestID: "myRequestID",
	}
	mockGetExecutionContext := func() executioncontext.ExecutionContext {
		return mockExecutionContext
	}
	mockUpdateExecutionContext := func(string, time.Time) {
		// do nothing
	}

	logCollection := &LambdaLogsCollector{
		LogsEnabled: true,
		LogChannel:  logChannel,
		ExtraTags: &Tags{
			Tags: []string{"tag0:value0,tag1:value1"},
		},
		GetExecutionContext:                mockGetExecutionContext,
		UpdateExecutionContextFromStartLog: mockUpdateExecutionContext,
	}

	logMessages := []logMessage{
		{
			stringRecord: "hi, log 2",
		},
	}
	go processLogMessages(logCollection, logMessages)

	select {
	case received := <-logChannel:
		assert.NotNil(t, received)
		assert.Equal(t, "myARN", received.Lambda.ARN)
		assert.Equal(t, "myRequestID", received.Lambda.RequestID)
	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "We should have received logs")
	}
}

func TestProcessLogMessageLogsNotEnabled(t *testing.T) {

	logChannel := make(chan *config.ChannelMessage)

	mockExecutionContext := executioncontext.ExecutionContext{
		ARN:           "myARN",
		LastRequestID: "myRequestID",
	}
	mockGetExecutionContext := func() executioncontext.ExecutionContext {
		return mockExecutionContext
	}
	mockUpdateExecutionContext := func(string, time.Time) {
		// do nothing
	}

	logCollection := &LambdaLogsCollector{
		LogsEnabled: false,
		LogChannel:  logChannel,
		ExtraTags: &Tags{
			Tags: []string{"tag0:value0,tag1:value1"},
		},
		GetExecutionContext:                mockGetExecutionContext,
		UpdateExecutionContextFromStartLog: mockUpdateExecutionContext,
	}

	logMessages := []logMessage{
		{
			stringRecord: "hi, log 0",
		},
		{
			stringRecord: "hi, log 1",
		},
		{
			stringRecord: "hi, log 2",
		},
	}
	go processLogMessages(logCollection, logMessages)

	select {
	case <-logChannel:
		assert.Fail(t, "We should not have received logs")
	case <-time.After(100 * time.Millisecond):
		// nothing to do here
	}
}

func TestServeHTTPInvalidPayload(t *testing.T) {
	logChannel := make(chan *config.ChannelMessage)

	mockExecutionContext := executioncontext.ExecutionContext{
		ARN:           "myARN",
		LastRequestID: "myRequestID",
	}
	mockGetExecutionContext := func() executioncontext.ExecutionContext {
		return mockExecutionContext
	}
	mockUpdateExecutionContext := func(string, time.Time) {
		// do nothing
	}

	logCollection := &LambdaLogsCollector{
		LogsEnabled: false,
		LogChannel:  logChannel,
		ExtraTags: &Tags{
			Tags: []string{"tag0:value0,tag1:value1"},
		},
		GetExecutionContext:                mockGetExecutionContext,
		UpdateExecutionContextFromStartLog: mockUpdateExecutionContext,
	}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	res := httptest.NewRecorder()

	logCollection.ServeHTTP(res, req)
	assert.Equal(t, 400, res.Code)
}

func TestServeHTTPSuccess(t *testing.T) {
	logChannel := make(chan *config.ChannelMessage)

	mockExecutionContext := executioncontext.ExecutionContext{
		ARN:           "myARN",
		LastRequestID: "myRequestID",
	}
	mockGetExecutionContext := func() executioncontext.ExecutionContext {
		return mockExecutionContext
	}
	mockUpdateExecutionContext := func(string, time.Time) {
		// do nothing
	}

	logCollection := &LambdaLogsCollector{
		LogsEnabled: false,
		LogChannel:  logChannel,
		ExtraTags: &Tags{
			Tags: []string{"tag0:value0,tag1:value1"},
		},
		GetExecutionContext:                mockGetExecutionContext,
		UpdateExecutionContextFromStartLog: mockUpdateExecutionContext,
	}

	raw, err := ioutil.ReadFile("./testdata/extension_log.json")
	if err != nil {
		assert.Fail(t, "should be able to read the log file")
	}
	if err != nil {
		assert.Fail(t, "should be able to marshal")
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	res := httptest.NewRecorder()

	logCollection.ServeHTTP(res, req)
	assert.Equal(t, 200, res.Code)
}

func TestUnmarshalJSONInvalid(t *testing.T) {
	logMessage := &logMessage{}
	err := logMessage.UnmarshalJSON([]byte("invalid"))
	assert.NotNil(t, err)
}

func TestUnmarshalJSONMalformed(t *testing.T) {
	logMessage := &logMessage{}
	raw, errReadFile := ioutil.ReadFile("./testdata/invalid_log_no_type.json")
	if errReadFile != nil {
		assert.Fail(t, "should be able to read the file")
	}
	err := logMessage.UnmarshalJSON(raw)
	assert.NotNil(t, err)
}

func TestUnmarshalJSONLogTypePlatformLogsSubscription(t *testing.T) {
	logMessage := &logMessage{}
	raw, errReadFile := ioutil.ReadFile("./testdata/platform_log.json")
	if errReadFile != nil {
		assert.Fail(t, "should be able to read the file")
	}
	err := logMessage.UnmarshalJSON(raw)
	assert.Nil(t, err)
	assert.Equal(t, "platform.logsSubscription", logMessage.logType)
}

func TestUnmarshalJSONLogTypePlatformStart(t *testing.T) {
	logMessage := &logMessage{}
	raw, errReadFile := ioutil.ReadFile("./testdata/platform_start.json")
	if errReadFile != nil {
		assert.Fail(t, "should be able to read the file")
	}
	err := logMessage.UnmarshalJSON(raw)
	assert.Nil(t, err)
	assert.Equal(t, "platform.start", logMessage.logType)
	assert.Equal(t, "START RequestId: 13dee504-0d50-4c86-8d82-efd20693afc9 Version: 10", logMessage.stringRecord)
}

func TestUnmarshalJSONLogTypePlatformEnd(t *testing.T) {
	logMessage := &logMessage{}
	raw, errReadFile := ioutil.ReadFile("./testdata/platform_end.json")
	if errReadFile != nil {
		assert.Fail(t, "should be able to read the file")
	}
	err := logMessage.UnmarshalJSON(raw)
	assert.Nil(t, err)
	assert.Equal(t, "platform.end", logMessage.logType)
	assert.Equal(t, "END RequestId: 13dee504-0d50-4c86-8d82-efd20693afc9", logMessage.stringRecord)
}

func TestUnmarshalJSONLogTypeIncorrectReportNotFatalMetrics(t *testing.T) {
	logMessage := &logMessage{}
	raw, errReadFile := ioutil.ReadFile("./testdata/platform_incorrect_report.json")
	if errReadFile != nil {
		assert.Fail(t, "should be able to read the file")
	}
	err := logMessage.UnmarshalJSON(raw)
	assert.Nil(t, err)
}

func TestUnmarshalJSONLogTypeIncorrectReportNotFatalReport(t *testing.T) {
	logMessage := &logMessage{}
	raw, errReadFile := ioutil.ReadFile("./testdata/platform_incorrect_report_record.json")
	if errReadFile != nil {
		assert.Fail(t, "should be able to read the file")
	}
	err := logMessage.UnmarshalJSON(raw)
	assert.Nil(t, err)
}

func TestUnmarshalPlatformRuntimeDoneLog(t *testing.T) {
	raw, err := ioutil.ReadFile("./testdata/platform_runtime_done_log_valid.json")
	require.NoError(t, err)
	var message logMessage
	err = json.Unmarshal(raw, &message)
	require.NoError(t, err)

	expectedTime := time.Date(2021, 05, 19, 18, 11, 22, 478000000, time.UTC)

	expectedLogMessage := logMessage{
		logType: logTypePlatformRuntimeDone,
		time:    expectedTime,
		objectRecord: platformObjectRecord{
			requestID: "13dee504-0d50-4c86-8d82-efd20693afc9",
			runtimeDoneItem: runtimeDoneItem{
				status: "success",
			},
		},
	}
	assert.Equal(t, expectedLogMessage, message)
}

func TestUnmarshalPlatformRuntimeDoneLogNotFatal(t *testing.T) {
	logMessage := &logMessage{}
	raw, errReadFile := ioutil.ReadFile("./testdata/platform_incorrect_runtime_done_log.json")
	if errReadFile != nil {
		assert.Fail(t, "should be able to read the file")
	}
	err := logMessage.UnmarshalJSON(raw)
	assert.Nil(t, err)
}
