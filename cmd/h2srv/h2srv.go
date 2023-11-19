package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
)

type PutRsp struct {
	Len int
}

// DataPut ...
func DataPut(w http.ResponseWriter, r *http.Request) {
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	rsp := &PutRsp{
		Len: len(buf),
	}

	// time.Sleep(100 * time.Millisecond)
	json.NewEncoder(w).Encode(&rsp)
	log.Println("Request len:", len(buf))
}

func startServer(maxUploadBuffer uint32) {

	r := mux.NewRouter()

	r.HandleFunc("/put", DataPut).Methods("POST")

	srv := &http.Server{
		Addr:    ":9001",
		Handler: r,
	}

	http2.ConfigureServer(srv, &http2.Server{
		MaxUploadBufferPerConnection: int32(maxUploadBuffer),
	})

	log.Fatal(srv.ListenAndServeTLS("certs/server.crt", "certs/server.key"))
	//log.Fatal(http.ListenAndServe(":9001", r))
}

func main() {
	//read maxUploadBuffer from cli arg
	maxUploadBuffer := uint64(65535)
	if len(os.Args) > 1 {
		maxUploadBuffer, _ = strconv.ParseUint(os.Args[1], 10, 32)
	}
	startServer(uint32(maxUploadBuffer))
}
