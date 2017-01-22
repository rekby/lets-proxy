package main

import (
	"net/http"
	"log"
	"fmt"
	"sort"
	"io/ioutil"
)

func main(){
	http.HandleFunc("/", func(resp http.ResponseWriter, req *http.Request){
		log.Println("http-ok:", req.RemoteAddr, req.Method, req.URL.String())
		resp.Header().Add("Content-type", "text/plain")

		names := []string{}
		for name := range req.Header {
			names = append(names, name)
		}

		if req.Host != "" {
			resp.Write([]byte("HOST: " + req.Host + "\r\n"))
			fmt.Fprintf(resp, "REMOTE: %v\r\n", req.RemoteAddr)
			resp.Write([]byte("\r\n\r\n"))
		}
		sort.Strings(names)
		for _, name := range names {
			values := req.Header[name]
			for _, value := range values {
				resp.Write([]byte(fmt.Sprintf("%v: %v\n", name, value)))
			}
		}

		resp.Write([]byte("\r\n"))
		requestBytes, _ := ioutil.ReadAll(req.Body)
		req.Body.Close()
		resp.Write(requestBytes)
	})
	server := &http.Server{Addr: ":80"}
	server.SetKeepAlivesEnabled(true)
	server.ListenAndServe()
}
