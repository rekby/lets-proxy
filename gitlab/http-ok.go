package main

import (
	"net/http"
	"log"
)

func main(){
	http.HandleFunc("/", func(resp http.ResponseWriter, req *http.Request){
		log.Println("http-ok:", req.RemoteAddr, req.Method, req.URL.String())
		resp.Header().Add("Content-type", "text/html")
		resp.Write([]byte("OK"))
	})
	http.ListenAndServe(":80", nil)
}
