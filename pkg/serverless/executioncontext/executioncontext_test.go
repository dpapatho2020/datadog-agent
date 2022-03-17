// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package executioncontext

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetCurrentState(t *testing.T) {
	assert := assert.New(t)

	testArn := "arn:aws:lambda:us-east-1:123456789012:function:MY-SUPER-function"
	testRequestID := "8286a188-ba32-4475-8077-530cd35c09a9"
	ec := ExecutionContext{}
	ec.SetFromInvocation(testArn, testRequestID)

	ecs := ec.GetCurrentState()
	assert.Equal(testRequestID, ecs.LastRequestID)
	assert.Equal(true, ecs.Coldstart)
	assert.Equal(testRequestID, ecs.ColdstartRequestID)
}

func TestSetFromInvocationUppercase(t *testing.T) {
	assert := assert.New(t)

	testArn := "arn:aws:lambda:us-east-1:123456789012:function:MY-SUPER-function"
	testRequestID := "8286a188-ba32-4475-8077-530cd35c09a9"
	ec := ExecutionContext{}
	ec.SetFromInvocation(testArn, testRequestID)

	assert.Equal("arn:aws:lambda:us-east-1:123456789012:function:my-super-function", ec.arn)
	assert.Equal(testRequestID, ec.lastRequestID)
	assert.Equal(true, ec.coldstart)
	assert.Equal(testRequestID, ec.coldstartRequestID)
}

func TestSetFromInvocationWarmStart(t *testing.T) {
	assert := assert.New(t)

	testArn := "arn:aws:lambda:us-east-1:123456789012:function:MY-SUPER-function"
	testRequestID := "8286a188-ba32-4475-8077-530cd35c09a9"

	ec := ExecutionContext{}
	ec.SetFromInvocation(testArn, "coldstart-request-id")
	ec.SetFromInvocation(testArn, testRequestID)

	assert.Equal("arn:aws:lambda:us-east-1:123456789012:function:my-super-function", ec.arn)
	assert.Equal(testRequestID, ec.lastRequestID)
	assert.Equal(false, ec.coldstart)
}

func TestUpdateFromStartLog(t *testing.T) {
	assert := assert.New(t)

	startTime := time.Now()
	testRequestID := "8286a188-ba32-4475-8077-530cd35c09a9"
	ec := ExecutionContext{}
	ec.UpdateFromStartLog(testRequestID, startTime)

	assert.Equal(testRequestID, ec.lastLogRequestID)
	assert.Equal(startTime, ec.startTime)
}

func TestSaveAndRestoreFromFile(t *testing.T) {
	assert := assert.New(t)

	testArn := "arn:aws:lambda:us-east-1:123456789012:function:my-super-function"
	testRequestID := "8286a188-ba32-4475-8077-530cd35c09a9"
	startTime := time.Now()
	ec := ExecutionContext{}
	ec.SetFromInvocation(testArn, testRequestID)
	ec.UpdateFromStartLog(testRequestID, startTime)

	err := ec.SaveCurrentExecutionContext()
	assert.Nil(err)

	ec.SetFromInvocation("this-arn-should-be-overwritten", "this-request-id-should-be-overwritten")

	err = ec.RestoreCurrentStateFromFile()
	assert.Nil(err)

	assert.Equal(testRequestID, ec.lastRequestID)
	assert.Equal(testArn, ec.arn)
}
