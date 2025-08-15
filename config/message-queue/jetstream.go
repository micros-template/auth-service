package messagequeue

import (
	_mq "github.com/micros-template/auth-service/internal/infrastructure/message-queue"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func NewJetstream(nc *nats.Conn) jetstream.JetStream {
	js, err := jetstream.New(nc)
	if err != nil {
		panic("failed to init jetstream")
	}
	// init notificationstream
	_mq.NewNotificationStream(js)
	return js
}
