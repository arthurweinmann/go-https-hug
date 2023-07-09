package acme

import "fmt"

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

func logthis(level LogLevel, mess string, args ...any) {
	if level >= settings.LogLevel {
		fmt.Printf(">    %s: %s\n", level, fmt.Sprintf(mess, args...))
	}
}
