package logemitter

import (
	"10.1.20.130/dropping/log-management/pkg"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

func NewInfraLogEmitter(js jetstream.JetStream, zerolog zerolog.Logger) pkg.LogEmitter {
	streamName := viper.GetString("jetstream.log.stream.name")
	streamDesc := viper.GetString("jetstream.log.stream.description")
	globalSubject := viper.GetString("jetstream.log.subject.global")
	subjectPrefix := viper.GetString("jetstream.log.subject.prefix")
	logEmitter := pkg.NewLogEmitter(js, zerolog, streamName, streamDesc, globalSubject, subjectPrefix)
	return logEmitter
}
