package utils

import (
	"log/slog"
)

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
	NONE
)

func (l LogLevel) String() string {
	switch l {
	default:
		return "UNRECOGNIZED LOG LEVEL"
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARNING:
		return "WARNING"
	case ERROR:
		return "ERROR"
	case NONE:
		return "NONE"
	}
}

func (l LogLevel) Sloglevel() slog.Level {
	switch l {
	default:
		return slog.LevelInfo
	case DEBUG:
		return slog.LevelDebug
	case INFO:
		return slog.LevelInfo
	case WARNING:
		return slog.LevelWarn
	case ERROR:
		return slog.LevelError
	}
}
