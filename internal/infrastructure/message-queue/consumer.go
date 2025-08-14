package messagequeue

import (
	event "10.1.20.130/dropping/event-bus-client/pkg/event/user"
	"10.1.20.130/dropping/log-management/pkg"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

func NewUserEventConsumerInfra(pgx *pgxpool.Pool, n Nats, logEmitter pkg.LogEmitter, logger zerolog.Logger) event.UserEventConsumer {
	cfg := jetstream.ConsumerConfig{
		Name:          viper.GetString("jetstream.event.consumer.user_event.name"),
		Durable:       viper.GetString("jetstream.event.consumer.user_event.name"),
		FilterSubject: viper.GetString("jetstream.event.consumer.user_event.subject"),
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverNewPolicy,
	}
	sn := viper.GetString("jetstream.event.stream.name")
	sd := viper.GetString("jetstream.event.stream.description")
	gs := viper.GetString("jetstream.event.subject.global")
	sen := "auth_service"
	con := event.NewUserEventConsumer(pgx, n.GetJetStream(), logEmitter, cfg, sen, sn, sd, gs, logger)
	return con
}
