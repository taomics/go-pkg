package log

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

type Severity int

const (
	Severity_DEFAULT   Severity = 0
	Severity_DEBUG     Severity = 100
	Severity_INFO      Severity = 200
	Severity_NOTICE    Severity = 300
	Severity_WARNING   Severity = 400
	Severity_ERROR     Severity = 500
	Severity_CRITICAL  Severity = 600
	Severity_ALERT     Severity = 700
	Severity_EMERGENCY Severity = 800
)

//nolint:cyclop
func (s Severity) MarshalJSON() ([]byte, error) {
	switch s {
	default:
		fallthrough
	case Severity_DEFAULT:
		return []byte(`"DEFAULT"`), nil
	case Severity_DEBUG:
		return []byte(`"DEBUG"`), nil
	case Severity_INFO:
		return []byte(`"INFO"`), nil
	case Severity_NOTICE:
		return []byte(`"NOTICE"`), nil
	case Severity_WARNING:
		return []byte(`"WARNING"`), nil
	case Severity_ERROR:
		return []byte(`"ERROR"`), nil
	case Severity_CRITICAL:
		return []byte(`"CRITICAL"`), nil
	case Severity_ALERT:
		return []byte(`"ALERT"`), nil
	case Severity_EMERGENCY:
		return []byte(`"EMERGENCY"`), nil
	}
}

type Entry struct {
	Severity Severity          `json:"severity"`
	Message  string            `json:"message,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

func Println(v ...any)               { _Println(v...) }
func Printf(format string, v ...any) { _Printf(format, v...) }
func Errorln(v ...any)               { _Errorln(v...) }
func Errorf(format string, v ...any) { _Errorf(format, v...) }
func Fatalln(v ...any)               { _Fatalln(v...) }
func Fatalf(format string, v ...any) { _Fatalf(format, v...) }
func Log(e *Entry) {
	if e == nil {
		return
	}

	if e.Severity < Severity_ERROR {
		infolog.JSONEncode(e)
	} else {
		errlog.JSONEncode(e)
	}
}

var (
	_Println = infoln
	_Printf  = infof
	_Errorln = errorln
	_Errorf  = errorf
	_Fatalln = fatalln
	_Fatalf  = fatalf
)

type logger struct {
	*log.Logger
	enc      *json.Encoder
	severity Severity
}

func (l logger) JSONEncode(e *Entry) {
	if e == nil {
		return
	}

	if e.Severity < l.severity {
		e.Severity = l.severity
	}

	if err := l.enc.Encode(e); err != nil {
		errorf(`{"severity":"ERROR","message":"%s: %+v"}`, err, e)
	}
}

var (
	infolog = logger{log.New(os.Stderr, "INFO: ", 0), json.NewEncoder(os.Stderr), Severity_INFO}
	errlog  = logger{log.New(os.Stderr, "ERROR: ", 0), json.NewEncoder(os.Stderr), Severity_ERROR}
	mux     sync.Mutex
)

func SetFlag(flag int) {
	infolog.SetFlags(flag)
	errlog.SetFlags(flag)
}

func SetPrefix(prefix string) {
	infolog.SetPrefix(prefix)
	errlog.SetPrefix(prefix)
}

func SetOutput(w io.Writer) {
	mux.Lock()
	defer mux.Unlock()

	infolog.SetOutput(w)
	infolog.enc = json.NewEncoder(w)
}

func SetErrorOutput(w io.Writer) {
	mux.Lock()
	defer mux.Unlock()

	errlog.SetOutput(w)
	errlog.enc = json.NewEncoder(w)
}

func EnableStructuredLogging(enable bool) {
	mux.Lock()
	defer mux.Unlock()

	//nolint:wsl
	if enable {
		_Println = jsonInfoln
		_Printf = jsonInfof
		_Errorln = jsonErrorln
		_Errorf = jsonErrorf
		_Fatalln = jsonFatalln
		_Fatalf = jsonFatalf
		infolog.SetFlags(0)
		infolog.SetPrefix("")
		errlog.SetFlags(0)
		errlog.SetPrefix("")
	} else {
		_Println = infoln
		_Printf = infof
		_Errorln = errorln
		_Errorf = errorf
		_Fatalln = fatalln
		_Fatalf = fatalf
	}
}

func infoln(v ...any) {
	infolog.Println(v...)
}

func infof(format string, v ...any) {
	infolog.Printf(format, v...)
}

func errorln(v ...any) {
	errlog.Println(v...)
}

func fatalln(v ...any) {
	if err := errlog.Output(3, fmt.Sprintln(v...)); err != nil { //nolint:mnd
		log.Println(err.Error())
		log.Println(v...)
	}

	os.Exit(1)
}

func fatalf(format string, v ...any) {
	if err := errlog.Output(3, fmt.Sprintf(format, v...)); err != nil { //nolint:mnd
		log.Println(err.Error())
		log.Printf(format, v...)
	}

	os.Exit(1)
}

func errorf(format string, v ...any) {
	errlog.Printf(format, v...)
}

func jsonInfoln(v ...any) {
	s := fmt.Sprintln(v...)
	infolog.JSONEncode(&Entry{Message: s[:len(s)-1]}) //nolint:exhaustruct
}

func jsonInfof(format string, v ...any) {
	infolog.JSONEncode(&Entry{Message: fmt.Sprintf(format, v...)}) //nolint:exhaustruct
}

func jsonErrorln(v ...any) {
	s := fmt.Sprintln(v...)
	errlog.JSONEncode(&Entry{Message: s[:len(s)-1]}) //nolint:exhaustruct
}

func jsonErrorf(format string, v ...any) {
	errlog.JSONEncode(&Entry{Message: fmt.Sprintf(format, v...)}) //nolint:exhaustruct
}

func jsonFatalln(v ...any) {
	jsonErrorln(v...)
	os.Exit(1)
}

func jsonFatalf(format string, v ...any) {
	jsonErrorf(format, v...)
	os.Exit(1)
}
