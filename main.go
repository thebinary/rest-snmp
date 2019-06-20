package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/soniah/gosnmp"
	"github.com/urfave/negroni"
)

// OidList - oids
type OidList struct {
	Oids []string `json:"oids"`
}

// GetFieldsRequest - set value maps
type GetFieldsRequest struct {
	Indexes []string `json:"indexes"`
	Fields  []string `json:"fields"`
}

// SetEntryRequest - set value maps
type SetEntryRequest struct {
	Values [][]interface{} `json:"values"`
}

// SNMPKey - key defining SNMP context key
type SNMPKey string

// SNMPKeyName - keyname defined for context
const SNMPKeyName SNMPKey = "SNMP"

// GetHandler - snmpget
func GetHandler(w http.ResponseWriter, r *http.Request) {
	g := r.Context().Value(SNMPKeyName).(*gosnmp.GoSNMP)
	defer g.Conn.Close()

	vars := mux.Vars(r)

	var oids []string
	var oidlist OidList
	if oid, ok := vars["oid"]; ok {

		// Specific oid request
		if r.ContentLength == 0 {
			oids = []string{oid}
		} else {
			// Request for combination of fields and indexes
			fieldsRequest := GetFieldsRequest{}
			err := json.NewDecoder(r.Body).Decode(&fieldsRequest)
			if err != nil {
				log.Printf("[ERR] decoding request json")
			}
			fields := fieldsRequest.Fields
			indexes := fieldsRequest.Indexes
			numIndexes := len(indexes)

			oids = make([]string, len(fields)*len(indexes))
			for i, index := range indexes {
				for j, foid := range fields {
					oids[i*(numIndexes+1)+j] = oid + "." + foid + "." + index
				}
			}
		}
	} else if baseOid, ok := vars["base_oid"]; ok {
		index := vars["index"]
		fieldsRequest := GetFieldsRequest{}
		err := json.NewDecoder(r.Body).Decode(&fieldsRequest)
		if err != nil {
			log.Printf("[ERR] decoding request json")
		}
		fields := fieldsRequest.Fields

		oids = make([]string, len(fields))
		for i, foid := range fields {
			oids[i] = baseOid + "." + foid + "." + index
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&oidlist); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte("oids missing"))
			if err != nil {
				log.Printf("[ERR] http write error")
			}
			return
		}
		oids = oidlist.Oids
	}

	if len(oids) <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		_, err := w.Write([]byte("Nothing to get"))
		if err != nil {
			log.Printf("[ERR] http write error")
		}
		return
	}

	result, err := g.Get(oids)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte(err.Error()))
		if err != nil {
			log.Printf("[ERR] http write error")
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(SanitizeResultVariables(&result.Variables))
	if err != nil {
		log.Printf("[ERR] encoding json")
	}
}

// WalkHandler - snmpwalk
func WalkHandler(w http.ResponseWriter, r *http.Request) {
	g := r.Context().Value(SNMPKeyName).(*gosnmp.GoSNMP)
	defer g.Conn.Close()

	vars := mux.Vars(r)
	rootOid := vars["base_oid"]

	result, err := g.WalkAll(rootOid)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte(err.Error()))
		if err != nil {
			log.Printf("[ERR] http write error")
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(SanitizeResultVariables(&result))
	if err != nil {
		log.Printf("[ERR] encoding json")
	}
}

// SetHandler - snmpset
func SetHandler(w http.ResponseWriter, r *http.Request) {
	g := r.Context().Value(SNMPKeyName).(*gosnmp.GoSNMP)
	defer g.Conn.Close()

	vars := mux.Vars(r)
	request := SetEntryRequest{}
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		log.Printf("[ERR] request body json decode")
	}
	baseOid := vars["base_oid"]
	index := vars["index"]

	var pdus []gosnmp.SnmpPDU

	// Adding Entry
	if r.Method == http.MethodPost {
		pdus = make([]gosnmp.SnmpPDU, len(request.Values)+1)
		rowOid := vars["row_oid"]
		rowOidArr := strings.Split(rowOid, ".")
		rowFieldOid := rowOidArr[len(rowOidArr)-1]
		baseOid = strings.Join(rowOidArr[:len(rowOidArr)-1], ".")

		pdus[0] = ToSnmpPDU(
			baseOid+"."+rowFieldOid+"."+index, "i", 4.0)

		for i, val := range request.Values {
			fieldOid := val[0].(string)
			fieldType := val[1]
			fieldValue := val[2]

			pdus[i+1] = ToSnmpPDU(baseOid+"."+fieldOid+"."+index, fieldType, fieldValue)
		}
	} else {
		pdus = make([]gosnmp.SnmpPDU, len(request.Values))
		if baseOid == "" {
			for i, val := range request.Values {
				oid := val[0].(string)
				fieldType := val[1]
				fieldValue := val[2]

				pdus[i] = ToSnmpPDU(oid, fieldType, fieldValue)
			}
		} else if index == "" {
			for i, val := range request.Values {
				oidSuffix := val[0]
				fieldType := val[1]
				fieldValue := val[2]

				pdus[i] = ToSnmpPDU(
					baseOid+"."+oidSuffix.(string), fieldType, fieldValue)
			}
		} else {
			for i, val := range request.Values {
				fieldOid := val[0].(string)
				fieldType := val[1]
				fieldValue := val[2]

				pdus[i] = ToSnmpPDU(
					baseOid+"."+fieldOid+"."+index,
					fieldType, fieldValue)
			}
		}
	}

	result, err := g.Set(pdus)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte(err.Error()))
		if err != nil {
			log.Printf("[ERR] http write error")
		}
		return
	}
	if result.ErrorIndex != 0 {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Set error: %v, Index: %v", result.Error, result.ErrorIndex)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(SanitizeResultVariables(&result.Variables))
	if err != nil {
		log.Printf("[ERR] encoding json")
	}
}

// DeleteHandler - snmpset with row delete
func DeleteHandler(w http.ResponseWriter, r *http.Request) {
	g := r.Context().Value(SNMPKeyName).(*gosnmp.GoSNMP)
	defer g.Conn.Close()

	vars := mux.Vars(r)
	rowOid := vars["row_oid"]
	index := vars["index"]
	oid := rowOid + "." + index
	log.Println(oid)

	pdus := []gosnmp.SnmpPDU{
		gosnmp.SnmpPDU{
			Name:  oid,
			Type:  gosnmp.Integer,
			Value: 6,
		},
	}

	getr, err := g.Get([]string{oid})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte(err.Error()))
		if err != nil {
			log.Printf("[ERR] http write error")
		}
		return
	}
	gpdus := getr.Variables
	log.Println(gpdus)
	// Does not exist
	if gpdus[0].Type != gosnmp.Integer {
		w.WriteHeader(http.StatusNotFound)
		_, err := w.Write([]byte("Entry does not exist"))
		if err != nil {
			log.Printf("[ERR] http write error")
		}
		return
	}

	result, err := g.Set(pdus)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte(err.Error()))
		if err != nil {
			log.Printf("[ERR] http write error")
		}
		return
	}
	if result.ErrorIndex != 0 {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Set error: %v, Index: %v", result.Error, result.ErrorIndex)
	}

	fmt.Fprint(w, "Entry deleted successfully")
}

const (
	addr = "0.0.0.0:8161"
)

func main() {
	var wait time.Duration
	flag.DurationVar(&wait, "graceful-timeout", time.Second*15, "the duration for which the server gracefully wait for existing connections to finish - e.g. 15s or 1m")
	flag.Parse()

	r := mux.NewRouter()

	snmprouter := r.PathPrefix("/api/v1/snmp/{snmp_version}/{target}").Subrouter()

	snmprouter.Handle("", AddSnmpContext(GetHandler)).Methods(http.MethodGet)
	snmprouter.Handle("/{oid}", AddSnmpContext(GetHandler)).Methods(http.MethodGet)
	snmprouter.Handle("/{base_oid}/{index}", AddSnmpContext(GetHandler)).Methods(http.MethodGet)

	snmprouter.Handle("/{base_oid}", AddSnmpContext(WalkHandler)).Methods("WALK")

	snmprouter.Handle("", AddSnmpContext(SetHandler)).Methods("SET")
	snmprouter.Handle("/{base_oid}", AddSnmpContext(SetHandler)).Methods(http.MethodPut)
	snmprouter.Handle("/{base_oid}/{index}", AddSnmpContext(SetHandler)).Methods(http.MethodPut)
	snmprouter.Handle("/{row_oid}/{index}", AddSnmpContext(SetHandler)).Methods(http.MethodPost)

	snmprouter.Handle("/{row_oid}/{index}", AddSnmpContext(DeleteHandler)).Methods(http.MethodDelete)

	nr := negroni.Classic()
	nr.UseHandler(r)

	srv := &http.Server{
		Addr: addr,
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      nr, // Pass our instance of gorilla/mux in.
	}

	// Run our server in a goroutine so that it doesn't block.
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal("Cannot listen on ", addr)
		}
	}()

	log.Println("Listening on ", addr)

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(c, os.Interrupt)

	<-c

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	err := srv.Shutdown(ctx)
	if err != nil {
		log.Println("[ERR] shutting down server")
	}
	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	log.Println("shutting down")
	os.Exit(0)
}
