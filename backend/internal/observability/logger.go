package observability

import (
	"io"
	"log/slog"
)

func NewJSONLogger(output io.Writer) *slog.Logger {
	return slog.New(
		slog.NewJSONHandler(
			output,
			&slog.HandlerOptions{
				Level: slog.LevelInfo,
			},
		),
	)
}
