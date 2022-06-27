package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

type LogLevel int

const (
	DebugLevel LogLevel = iota
	InfoLevel
	WarningLevel
	ErrorLevel
)

type Logger struct {
	loggers map[LogLevel]*log.Logger
}

var DefaultLogLevel = InfoLevel

func UpdateDefaultLogLevel(level string) {
	DefaultLogLevel = parseLogLevelFromString(level)
}

func parseLogLevelFromString(level string) LogLevel {
	switch strings.ToLower(level) {
	case "deb", "debug":
		return DebugLevel
	case "inf", "info":
		return InfoLevel
	case "war", "warn", "warning":
		return WarningLevel
	case "err", "error":
		return ErrorLevel
	default:
		return InfoLevel
	}
}

func NewLogger(prefix string, writer io.Writer, flags int) *Logger {
	if len(prefix) == 0 {
		prefix = "default"
	}

	return &Logger{
		loggers: map[LogLevel]*log.Logger{
			DebugLevel:   log.New(writer, fmt.Sprintf("\033[0;32m[DEBUG]\033[0m %s - ", prefix), flags),
			InfoLevel:    log.New(writer, fmt.Sprintf("\033[0;34m[INFO]\033[0m %s - ", prefix), flags),
			WarningLevel: log.New(writer, fmt.Sprintf("\033[0;33m[WARNING]\033[0m %s - ", prefix), flags),
			ErrorLevel:   log.New(writer, fmt.Sprintf("\033[0;31m[ERROR]\033[0m %s - ", prefix), flags),
		},
	}
}

func NewLoggerWithName(name string) *Logger {
	return NewLogger(name, os.Stdout, log.Lmsgprefix|log.Ldate|log.Ltime)
}

func (l *Logger) write(logLevel LogLevel, msg string, data ...interface{}) {
	if DefaultLogLevel <= logLevel {
		l.loggers[logLevel].Printf(msg, data...)
	}
}

func (l *Logger) Debug(msg string, data ...interface{}) {
	l.write(DebugLevel, msg, data...)
}

func (l *Logger) Info(msg string, data ...interface{}) {
	l.write(InfoLevel, msg, data...)
}

func (l *Logger) Warn(msg string, data ...interface{}) {
	l.write(WarningLevel, msg, data...)
}

func (l *Logger) Error(msg string, data ...interface{}) {
	l.write(ErrorLevel, msg, data...)
}
