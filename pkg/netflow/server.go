// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2020-present Datadog, Inc.

package netflow

import (
	"time"

	"github.com/DataDog/datadog-agent/pkg/aggregator"
	coreconfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/netflow/config"
	"github.com/DataDog/datadog-agent/pkg/netflow/flowaggregator"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var serverInstance *Server

// Server manages netflow listeners.
type Server struct {
	Addr          string
	config        *config.NetflowConfig
	listeners     []*netflowListener
	demultiplexer aggregator.Demultiplexer
	flowAgg       *flowaggregator.FlowAggregator
}

// Stop stops the Server.
func (s *Server) Stop() {
	log.Infof("Stop NetFlow Server")

	s.flowAgg.Stop()

	for _, listener := range s.listeners {
		log.Infof("Stop listening on %s", listener.config.Addr())
		stopped := make(chan interface{})

		go func() {
			log.Infof("Stop listening on %s", listener.config.Addr())
			listener.shutdown()
			close(stopped)
		}()

		select {
		case <-stopped:
		case <-time.After(time.Duration(s.config.StopTimeout) * time.Second):
			log.Errorf("Stopping server. Timeout after %d seconds", s.config.StopTimeout)
		}
	}
}

// StartServer starts the global NetFlow collector.
func StartServer(demultiplexer aggregator.Demultiplexer) error {
	server, err := NewNetflowServer(demultiplexer)
	if err != nil {
		serverInstance = server
	}
	return err
}

// StopServer stops the netflow server, if it is running.
func StopServer() {
	if serverInstance != nil {
		serverInstance.Stop()
		serverInstance = nil
	}
}

// NewNetflowServer configures and returns a running SNMP traps server.
func NewNetflowServer(demultiplexer aggregator.Demultiplexer) (*Server, error) {
	var listeners []*netflowListener

	mainConfig, err := config.ReadConfig()
	if err != nil {
		return nil, err
	}

	sender, err := demultiplexer.GetDefaultSender()
	if err != nil {
		return nil, err
	}

	flowAgg := flowaggregator.NewFlowAggregator(sender, mainConfig)
	go flowAgg.Start()

	for _, listenerConfig := range mainConfig.Listeners {
		log.Infof("Starting Netflow listener for flow type %s on %s", listenerConfig.FlowType, listenerConfig.Addr())
		listener, err := startFlowListener(listenerConfig, flowAgg)
		if err != nil {
			log.Warnf("Error starting listener for config (flow_type:%s, bind_Host:%s, port:%d)", listenerConfig.FlowType, listenerConfig.BindHost, listenerConfig.Port)
			continue
		}
		listeners = append(listeners, listener)
	}

	return &Server{
		listeners:     listeners,
		demultiplexer: demultiplexer,
		config:        mainConfig,
		flowAgg:       flowAgg,
	}, nil
}

// IsEnabled returns whether NetFlow collection is enabled in the Agent configuration.
func IsEnabled() bool {
	return coreconfig.Datadog.GetBool("network_devices.netflow.enabled")
}