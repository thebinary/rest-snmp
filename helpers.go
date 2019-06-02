package main

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/soniah/gosnmp"
)

// ToSnmpPDU - convert to SnmpPDU
func ToSnmpPDU(oid string, typeString interface{}, value interface{}) gosnmp.SnmpPDU {
	var pduType gosnmp.Asn1BER
	var pduValue interface{}

	// TODO : Test all the types
	switch typeString.(string) {
	case "i":
		pduType = gosnmp.Integer
		pduValue = int(value.(float64))
	case "u":
		pduType = gosnmp.Uinteger32
		pduValue = int(value.(float64))
	case "t":
		pduType = gosnmp.TimeTicks
		pduValue = int(value.(float64))
	case "a":
		pduType = gosnmp.IPAddress
		pduValue = value.([]byte)
	case "o":
		pduType = gosnmp.ObjectIdentifier
		pduValue = value.([]byte)
	case "s", "x":
		pduType = gosnmp.OctetString
		pduValue = value.(string)
	case "b":
		pduType = gosnmp.BitString
		pduValue = value.(string)
	default:
		return gosnmp.SnmpPDU{}
	}

	return gosnmp.SnmpPDU{
		Name:  oid,
		Type:  pduType,
		Value: pduValue,
	}
}

// AddSnmpContext - snmp connection wrapper handler
func AddSnmpContext(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		sversionLabel := vars["snmp_version"]
		starget := vars["target"]
		scommunity := r.Header.Get("X-SNMP-COMM")
		var sversion gosnmp.SnmpVersion

		switch sversionLabel {
		case "v1":
			sversion = gosnmp.Version1
		case "v2", "v2c":
			sversion = gosnmp.Version2c
		default:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Unknown SNMP version"))
			return
		}

		if scommunity == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("SNMP Community undefined"))
			return
		}

		g := gosnmp.Default
		g.Target = starget
		g.Community = scommunity
		g.Version = sversion

		err := g.Connect()
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(err.Error()))
			return
		}

		ctx := context.WithValue(r.Context(), SNMPKeyName, g)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// SanitizeResultVariables - refactor gosnmp result variables
func SanitizeResultVariables(pdus *[]gosnmp.SnmpPDU) []gosnmp.SnmpPDU {
	pdusNew := *pdus
	for i, p := range pdusNew {
		if pdusNew[i].Type == gosnmp.OctetString {
			pdusNew[i].Value = string(p.Value.([]byte))
		}
	}
	return pdusNew
}
