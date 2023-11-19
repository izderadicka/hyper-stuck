package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"

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

func startServer(maxUploadBuffer int32, maxStreams uint32) {

	r := mux.NewRouter()

	r.HandleFunc("/put", DataPut).Methods("POST")

	srv := &http.Server{
		Addr:    ":9001",
		Handler: r,
	}

	http2.ConfigureServer(srv, &http2.Server{
		MaxUploadBufferPerConnection: maxUploadBuffer,
		MaxConcurrentStreams:         maxStreams,
	})

	log.Fatal(srv.ListenAndServeTLS("certs/server.crt", "certs/server.key"))
	//log.Fatal(http.ListenAndServe(":9001", r))
}

func main() {
	maxUploadBuffer := flag.Uint64("upload-buffer", 65535, "maximum upload buffer size")
	maxStreams := flag.Uint("streams", 100, "maximum number of concurrent streams")

	flag.Parse()
	startServer(int32(*maxUploadBuffer), uint32(*maxStreams))
}
