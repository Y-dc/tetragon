// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
)

func main() {
	go goPprof()
	if err := execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func goPprof() {
	router := gin.New()
	pprof.Register(router)
	httpServer := &http.Server{
		Addr:         ":9999",
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 2 * time.Minute,
		IdleTimeout:  13 * time.Minute,
	}

	log.Println("开始服务")
	log.Fatal(httpServer.ListenAndServe())
}