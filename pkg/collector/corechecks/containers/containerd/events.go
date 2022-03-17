// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build containerd
// +build containerd

package containerd

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/events"
	containerdevents "github.com/containerd/containerd/events"
	"github.com/gogo/protobuf/proto"

	"github.com/DataDog/datadog-agent/pkg/aggregator"
	coreMetrics "github.com/DataDog/datadog-agent/pkg/metrics"
	"github.com/DataDog/datadog-agent/pkg/tagger"
	"github.com/DataDog/datadog-agent/pkg/tagger/collectors"
	ctrUtil "github.com/DataDog/datadog-agent/pkg/util/containerd"
	ddContainers "github.com/DataDog/datadog-agent/pkg/util/containers"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// compute events converts Containerd events into Datadog events
func computeEvents(events []containerdEvent, sender aggregator.Sender, fil *ddContainers.Filter) {
	for _, e := range events {
		split := strings.Split(e.Topic, "/")
		if len(split) != 3 {
			// sanity checking the event, to avoid submitting
			log.Debugf("Event topic %s does not have the expected format", e.Topic)
			continue
		}
		if split[1] == "images" && fil.IsExcluded("", e.ID, "") {
			continue
		}
		output := coreMetrics.Event{
			Priority:       coreMetrics.EventPriorityNormal,
			SourceTypeName: containerdCheckName,
			EventType:      containerdCheckName,
			AggregationKey: fmt.Sprintf("containerd:%s", e.Topic),
		}
		output.Text = e.Message
		if len(e.Extra) > 0 {
			for k, v := range e.Extra {
				output.Tags = append(output.Tags, fmt.Sprintf("%s:%s", k, v))
			}
		}
		output.Ts = e.Timestamp.Unix()
		output.Title = fmt.Sprintf("Event on %s from Containerd", split[1])
		if split[1] == "containers" || split[1] == "tasks" {
			// For task events, we use the container ID in order to query the Tagger's API
			tags, err := tagger.Tag(ddContainers.ContainerEntityPrefix+e.ID, collectors.HighCardinality)
			if err != nil {
				// If there is an error retrieving tags from the Tagger, we can still submit the event as is.
				log.Errorf("Could not retrieve tags for the container %s: %v", e.ID, err)
			}
			output.Tags = append(output.Tags, tags...)
		}
		sender.Event(output)
	}
}

// containerdEvent contains the timestamp to make sure we flush all events that happened between two checks
type containerdEvent struct {
	ID        string
	Timestamp time.Time
	Topic     string
	Namespace string
	Message   string
	Extra     map[string]string
}

func processMessage(id string, message *containerdevents.Envelope) containerdEvent {
	return containerdEvent{
		ID:        id,
		Timestamp: message.Timestamp,
		Topic:     message.Topic,
		Namespace: message.Namespace,
	}
}

type subscriber struct {
	Name                string
	Filters             []string
	Events              []containerdEvent
	CollectionTimestamp int64
	running             bool
}

func createEventSubscriber(name string, f []string) *subscriber {
	return &subscriber{
		Name:                name,
		CollectionTimestamp: time.Now().Unix(),
		Filters:             f,
	}
}

func (s *subscriber) CheckEvents(ctrItf ctrUtil.ContainerdItf) {
	ctx := context.Background()
	ev := ctrItf.GetEvents()
	log.Info("Starting routine to collect Containerd events ...")
	go s.run(ctx, ev) //nolint:errcheck
}

// Run should only be called once, at start time
func (s *subscriber) run(ctx context.Context, ev containerd.EventService) error {
	s.Lock()
	if s.running {
		s.Unlock()
		return fmt.Errorf("subscriber is already running the event listener routine")
	}
	stream, errC := ev.Subscribe(ctx, s.Filters...)
	s.running = true
	s.Unlock()
	for {
		select {
		case message := <-stream:
			switch message.Topic {
			case "/containers/create":
				create := &events.ContainerCreate{}
				err := proto.Unmarshal(message.Event.Value, create)
				if err != nil {
					log.Errorf("Could not process create event from Containerd: %v", err)
					continue
				}
				event := processMessage(create.ID, message)
				event.Message = fmt.Sprintf("Container %s started, running the image %s", create.ID, create.Image)
				s.addEvents(event)
			case "/containers/delete":
				delete := &events.ContainerDelete{}
				err := proto.Unmarshal(message.Event.Value, delete)
				if err != nil {
					log.Errorf("Could not process delete event from Containerd: %v", err)
					continue
				}
				event := processMessage(delete.ID, message)
				event.Message = fmt.Sprintf("Container %s deleted", delete.ID)
				s.addEvents(event)
			case "/containers/update":
				updated := &events.ContainerUpdate{}
				err := proto.Unmarshal(message.Event.Value, updated)
				if err != nil {
					log.Errorf("Could not process update event from Containerd: %v", err)
					continue
				}
				event := processMessage(updated.ID, message)
				event.Message = fmt.Sprintf("Container %s updated, running image %s. Snapshot key: %s", updated.ID, updated.Image, updated.SnapshotKey)
				event.Extra = updated.Labels
				s.addEvents(event)
			case "/images/update":
				updated := &events.ImageUpdate{}
				err := proto.Unmarshal(message.Event.Value, updated)
				if err != nil {
					log.Errorf("Could not process update event from Containerd: %v", err)
					continue
				}
				event := processMessage(updated.Name, message)
				event.Extra = updated.Labels
				event.Message = fmt.Sprintf("Image %s updated", updated.Name)
				s.addEvents(event)
			case "/images/create":
				created := &events.ImageCreate{}
				err := proto.Unmarshal(message.Event.Value, created)
				if err != nil {
					log.Errorf("Could not process create event from Containerd: %v", err)
					continue
				}

				event := processMessage(created.Name, message)
				event.Message = fmt.Sprintf("Image %s created", created.Name)
				event.Extra = created.Labels
				s.addEvents(event)
			case "/images/delete":
				deleted := &events.ImageDelete{}
				err := proto.Unmarshal(message.Event.Value, deleted)
				if err != nil {
					log.Errorf("Could not process delete event from Containerd: %v", err)
					continue
				}
				event := processMessage(deleted.Name, message)
				event.Message = fmt.Sprintf("Image %s created", deleted.Name)
				s.addEvents(event)
			case "/tasks/create":
				created := &events.TaskCreate{}
				err := proto.Unmarshal(message.Event.Value, created)
				if err != nil {
					log.Errorf("Could not process create event from Containerd: %v", err)
					continue
				}
				event := processMessage(created.ContainerID, message)
				event.Message = fmt.Sprintf("Task %s created with PID %d", created.ContainerID, created.Pid)
				s.addEvents(event)
			case "/tasks/delete":
				deleted := &events.TaskDelete{}
				err := proto.Unmarshal(message.Event.Value, deleted)
				if err != nil {
					log.Errorf("Could not process delete event from Containerd: %v", err)
					continue
				}
				event := processMessage(deleted.ContainerID, message)
				event.Message = fmt.Sprintf("Task %s deleted with exit code %d", deleted.ContainerID, deleted.ExitStatus)
				s.addEvents(event)
			case "/tasks/exit":
				exited := &events.TaskExit{}
				err := proto.Unmarshal(message.Event.Value, exited)
				if err != nil {
					log.Errorf("Could not process exit event from Containerd: %v", err)
					continue
				}

				event := processMessage(exited.ContainerID, message)
				event.Message = fmt.Sprintf("Task %s exited with exit code %d", exited.ContainerID, exited.ExitStatus)
				s.addEvents(event)
			case "/tasks/oom":
				oomed := &events.TaskOOM{}
				err := proto.Unmarshal(message.Event.Value, oomed)
				if err != nil {
					log.Errorf("Could not process create event from Containerd: %v", err)
					continue
				}
				event := processMessage(oomed.ContainerID, message)
				event.Message = fmt.Sprintf("Task %s ran out of memory", oomed.ContainerID)
				s.addEvents(event)
			case "/tasks/paused":
				paused := &events.TaskPaused{}
				err := proto.Unmarshal(message.Event.Value, paused)
				if err != nil {
					log.Errorf("Could not process create event from Containerd: %v", err)
					continue
				}

				event := processMessage(paused.ContainerID, message)
				event.Message = fmt.Sprintf("Task %s was paused", paused.ContainerID)
				s.addEvents(event)
			case "/tasks/resumed":
				resumed := &events.TaskResumed{}
				err := proto.Unmarshal(message.Event.Value, resumed)
				if err != nil {
					log.Errorf("Could not process create event from Containerd: %v", err)
					continue
				}
				event := processMessage(resumed.ContainerID, message)
				event.Message = fmt.Sprintf("Task %s was resumed", resumed.ContainerID)
				s.addEvents(event)
			default:
				log.Tracef("Unsupported event type from Containerd: %s ", message.Topic)
			}
		case e := <-errC:
			// As we only collect events from one containerd namespace, using this bool is sufficient.
			s.Lock()
			s.running = false
			s.Unlock()
			if e == context.Canceled {
				log.Debugf("Context of the event listener routine was canceled")
				return nil
			}
			log.Errorf("Error while streaming logs from containerd: %s", e.Error())
			return fmt.Errorf("stopping Containerd event listener routine")
		}
	}
}

func (s *subscriber) addEvents(event containerdEvent) {
	s.Lock()
	s.Events = append(s.Events, event)
	s.Unlock()
}

func (s *subscriber) isRunning() bool {
	s.Lock()
	defer s.Unlock()
	return s.running
}

// Flush should be called every time you want to get the list of events that have been received since the last Flush
func (s *subscriber) Flush(timestamp int64) []containerdEvent {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	delta := s.CollectionTimestamp - timestamp
	if len(s.Events) == 0 {
		log.Tracef("No events collected in the last %d seconds", delta)
		return nil
	}
	s.CollectionTimestamp = timestamp
	ev := s.Events
	log.Debugf("Collecting %d events from Containerd", len(ev))
	s.Events = nil
	return ev
}
