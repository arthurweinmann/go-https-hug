package router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

type JSONErr struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Code    string `json:"code,omitempty"`
}

func MarshalJSONErr(message, code string, args ...any) []byte {
	b, err := json.Marshal(&JSONErr{
		Success: false,
		Message: fmt.Sprintf(message, args...),
		Code:    code,
	})
	if err != nil {
		panic(err)
	}
	return b
}

func UnmarshalJSONErr(b []byte) *JSONErr {
	jserr := &JSONErr{}

	err := json.Unmarshal(b, jserr)
	if err != nil {
		jserr.Code = "invalidError"
		jserr.Message = fmt.Sprintf("Error decoding JSON Err: %v: %v", err, strconv.Quote(string(b)))
	}

	return jserr
}

func SendInternalError(w http.ResponseWriter, origin string, err error) {
	fmt.Println("Error", "origin", origin, "error", err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(501)
	b, _ := json.Marshal(&JSONErr{
		Success: false,
		Message: "it looks like we have an issue on our side, please retry later",
		Code:    "internal",
	})
	w.Write(b)
}

func SendError(w http.ResponseWriter, message, code string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	b, _ := json.Marshal(&JSONErr{
		Success: false,
		Message: message,
		Code:    code,
	})
	w.Write(b)
}

func SendErrorAndLog(w http.ResponseWriter, message, code string, statusCode int, origin string, err error) {
	fmt.Println("Error", origin, message, code, err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	b, _ := json.Marshal(&JSONErr{
		Success: false,
		Message: message,
		Code:    code,
	})
	w.Write(b)
}

func SendSuccess(w http.ResponseWriter, resp interface{}) {
	w.WriteHeader(200)
	w.Header().Add("Content-Type", "application/json")

	if resp == nil {
		w.Write([]byte(`{"success": true}`))
		return
	}

	b, err := JSONMarshal(resp)
	if err != nil {
		SendError(w, err.Error(), "invalidresponse", 501)
		return
	}

	w.Write(b)
}

// JSONMarshal does not escape HTML
func JSONMarshal(t interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(t)
	return buffer.Bytes(), err
}
