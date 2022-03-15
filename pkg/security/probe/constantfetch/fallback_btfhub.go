// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package constantfetch

import (
	"fmt"
	"runtime"

	"github.com/DataDog/datadog-agent/pkg/security/ebpf/kernel"
)

// BTFHubConstantFetcher is a constant fetcher based on BTFHub constants
type BTFHubConstantFetcher struct {
	kernelVersion *kernel.Version
	res           map[string]uint64
}

var idToDistribMapping = map[string]string{
	"ubuntu": "ubuntu",
	"debian": "debian",
	"amzn":   "amzn",
	"centos": "centos",
}

var archMapping = map[string]string{
	"amd64": "x86_64",
	"arm64": "arm64",
}

// NewBTFHubConstantFetcher returns a new BTFHubConstantFetcher
func NewBTFHubConstantFetcher(kv *kernel.Version) *BTFHubConstantFetcher {
	fetcher := &BTFHubConstantFetcher{
		kernelVersion: kv,
		res:           make(map[string]uint64),
	}

	kernelInfos, ok := NewKernelInfos(kv)
	if ok {
		fmt.Println(kernelInfos)
	}

	return fetcher
}

type kernelInfos struct {
	distribution   string
	distribVersion string
	arch           string
	unameRelease   string
}

func NewKernelInfos(kv *kernel.Version) (*kernelInfos, bool) {
	releaseID, ok := kv.OsRelease["ID"]
	if !ok {
		return nil, false
	}

	distribution, ok := idToDistribMapping[releaseID]
	if !ok {
		return nil, false
	}

	version, ok := kv.OsRelease["VERSION_ID"]
	if !ok {
		return nil, false
	}

	arch, ok := archMapping[runtime.GOARCH]
	if !ok {
		return nil, false
	}

	return &kernelInfos{
		distribution:   distribution,
		distribVersion: version,
		arch:           arch,
		unameRelease:   kv.UnameRelease,
	}, true
}

type BTFHubConstantsInfo struct {
	Distribution   string            `json:"distrib"`
	DistribVersion string            `json:"version"`
	Arch           string            `json:"arch"`
	UnameRelease   string            `json:"uname_release"`
	Constants      map[string]uint64 `json:"constants"`
}
