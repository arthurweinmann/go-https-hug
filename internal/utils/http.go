package utils

import (
	"bufio"
	"context"
	"encoding/base32"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

func UploadFileMultipart(client *http.Client, url string, path string) (*http.Response, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}

	// Reduce number of syscalls when reading from disk.
	bufferedFileReader := bufio.NewReader(f)
	defer f.Close()

	// Create a pipe for writing from the file and reading to
	// the request concurrently.
	bodyReader, bodyWriter := io.Pipe()
	formWriter := multipart.NewWriter(bodyWriter)

	// Store the first write error in writeErr.
	var (
		writeErr error
		errOnce  sync.Once
	)
	setErr := func(err error) {
		if err != nil {
			errOnce.Do(func() { writeErr = err })
		}
	}
	go func() {
		partWriter, err := formWriter.CreateFormFile("file", filepath.Base(path))
		setErr(err)
		if err != nil {
			fmt.Println("formWriter.CreateFormFile", err)
		} else {
			for {
				n, err := io.CopyN(partWriter, bufferedFileReader, 1024*1024*5)
				if err != nil {
					if err != io.EOF {
						setErr(err)
					}
					break
				}
				if n == 0 {
					break
				}
			}
		}

		// _, err = io.Copy(partWriter, bufferedFileReader)
		setErr(err)
		setErr(formWriter.Close())
		setErr(bodyWriter.Close())
	}()

	req, err := http.NewRequest(http.MethodPut, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", formWriter.FormDataContentType())

	// This operation will block until both the formWriter
	// and bodyWriter have been closed by the goroutine,
	// or in the event of a HTTP error.
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("3", err)
		return nil, err
	}

	if writeErr != nil {
		return nil, writeErr
	}

	return resp, err
}

func UploadFolderMultipart(client *http.Client, url, method string, folder string, fields ...string) (*http.Response, error) {

	// Create a pipe for writing from the file and reading to
	// the request concurrently.
	bodyReader, bodyWriter := io.Pipe()
	formWriter := multipart.NewWriter(bodyWriter)

	// Store the first write error in writeErr.
	var (
		writeErr error
		errOnce  sync.Once
	)
	setErr := func(err error) {
		if err != nil {
			errOnce.Do(func() { writeErr = err })
		}
	}
	go func() {
		err := filepath.Walk(folder, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			rel, err := filepath.Rel(folder, path)
			if err != nil {
				return err
			}

			partWriter, err := formWriter.CreateFormFile("file", rel)
			if err != nil {
				return err
			}

			f, err := os.OpenFile(path, os.O_RDONLY, 0644)
			if err != nil {
				return err
			}

			// Reduce number of syscalls when reading from disk.
			bufferedFileReader := bufio.NewReader(f)
			defer f.Close()

			for {
				n, err := io.CopyN(partWriter, bufferedFileReader, 1024*1024*5)
				if err != nil {
					if err != io.EOF {
						return err
					}
					break
				}
				if n == 0 {
					break
				}
			}

			return nil
		})

		// _, err = io.Copy(partWriter, bufferedFileReader)
		setErr(err)

		if err == nil {
			for i := 0; i < len(fields); i += 2 {
				err := formWriter.WriteField(fields[i], fields[i+1])
				if err != nil {
					setErr(err)
					break
				}
			}
		}

		setErr(formWriter.Close())
		setErr(bodyWriter.Close())
	}()

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", formWriter.FormDataContentType())

	// This operation will block until both the formWriter
	// and bodyWriter have been closed by the goroutine,
	// or in the event of a HTTP error.
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if writeErr != nil {
		return nil, writeErr
	}

	return resp, err
}

func UploadEmbedFolderMultipart(client *http.Client, url, method string, relfilepaths []string, files []fs.File, fields ...string) (*http.Response, error) {

	// Create a pipe for writing from the file and reading to
	// the request concurrently.
	bodyReader, bodyWriter := io.Pipe()
	formWriter := multipart.NewWriter(bodyWriter)

	// Store the first write error in writeErr.
	var (
		writeErr error
		errOnce  sync.Once
	)
	setErr := func(err error) {
		if err != nil {
			errOnce.Do(func() { writeErr = err })
		}
	}
	go func() {
		for i := 0; i < len(relfilepaths); i++ {
			rel := relfilepaths[i]
			f := files[i]

			partWriter, err := formWriter.CreateFormFile("file", base32.StdEncoding.EncodeToString([]byte(rel)))
			if err != nil {
				setErr(err)
				return
			}

			// Reduce number of syscalls when reading from disk.
			bufferedFileReader := bufio.NewReader(f)

			for {
				n, err := io.CopyN(partWriter, bufferedFileReader, 1024*1024*5)
				if err != nil {
					if err != io.EOF {
						setErr(err)
						return
					}
					break
				}
				if n == 0 {
					break
				}
			}
		}

		for i := 0; i < len(fields); i += 2 {
			err := formWriter.WriteField(fields[i], fields[i+1])
			if err != nil {
				setErr(err)
				break
			}
		}

		setErr(formWriter.Close())
		setErr(bodyWriter.Close())
	}()

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", formWriter.FormDataContentType())

	// This operation will block until both the formWriter
	// and bodyWriter have been closed by the goroutine,
	// or in the event of a HTTP error.
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if writeErr != nil {
		return nil, writeErr
	}

	return resp, err
}

func ForceIPHTTPClient(ip, port string) *http.Client {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		// DualStack: true, // this is deprecated as of go 1.16
	}

	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, ip+":"+port)
			},
		},
		Timeout: 60 * time.Second,
	}
}

func ForceIPWebsocketDialer(ip, port string) *websocket.Dialer {
	netdialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		// DualStack: true, // this is deprecated as of go 1.16
	}

	return &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			return netdialer.DialContext(context.Background(), network, ip+":"+port)
		},
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return netdialer.DialContext(ctx, network, ip+":"+port)
		},
		HandshakeTimeout: 60 * time.Second,
	}
}
