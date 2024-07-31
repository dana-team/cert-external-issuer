package common

import "k8s.io/client-go/tools/record"

const (
	EventSource = "cert-external-issuer"
)

// CollectEvents returns a string slice collecting all events from the recorder.
func CollectEvents(eventRecorder *record.FakeRecorder) []string {
	var actualEvents []string
	for {
		select {
		case e := <-eventRecorder.Events:
			actualEvents = append(actualEvents, e)
		default:
			return actualEvents
		}
	}
}
