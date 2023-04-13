package mock

/*
 * Copyright 2021 kloeckner.i GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import (
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/db-operator/cloudish-sql/pubkey"
	"github.com/db-operator/cloudish-sql/util"
	"github.com/gorilla/mux"
	"github.com/sdomino/scribble"
	log "github.com/sirupsen/logrus"
	"google.golang.org/api/googleapi"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

/* #nosec. */
const allowedBearerToken = "let-me-in-pls"

// SQLAdminAPI is a mocked version of the Google sqladmin API.
type SQLAdminAPI struct {
	DB        *scribble.Driver
	dbProxy   *DatabaseProxy
	authority *pubkey.Authority
	apiPort   int
}

var errInvalidBody = fmt.Errorf("get instance invalid body nil")

// NewSQLAdminAPI constructs a new mocked sqladmin API.
func NewSQLAdminAPI(dbProxy *DatabaseProxy, authority *pubkey.Authority, apiPort int) (*SQLAdminAPI, error) {
	db, err := scribble.New("data", nil)
	if err != nil {
		log.Error("can not set up scribble db", err)
	}

	return &SQLAdminAPI{db, dbProxy, authority, apiPort}, nil
}

// Run runs the mocked sqladmin API.
func (sql *SQLAdminAPI) Run() error {
	router := mux.NewRouter()

	router.HandleFunc("/health", sql.healthCheckRequestHandler).Methods("GET")
	router.HandleFunc("/sql/v1beta4/projects/{project}/instances/{instance}", sql.getInstanceHandler).Methods("GET")
	router.HandleFunc("/sql/v1beta4/projects/{project}/instances", sql.createInstanceHandler).Methods("POST")
	router.HandleFunc("/sql/v1beta4/projects/{project}/instances/{instance}/createEphemeral",
		sql.createEphemeralHandler).Methods("POST")
	router.HandleFunc("/sql/v1beta4/projects/{project}/instances/{instance}", sql.patchInstanceHandler).Methods("PATCH")
	router.HandleFunc("/sql/v1beta4/projects/{project}/instances/{instance}/users", sql.updateUserHandler).Methods("PUT")

	// Custom extension to the API for testing
	router.HandleFunc("/revoke", sql.revokeCertificatesHandler)

	return http.ListenAndServe(fmt.Sprintf(":%d", sql.apiPort), router)
}

func (sql *SQLAdminAPI) getInstanceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Infof("get instance called - %s %s", vars["project"], vars["instance"])

	w.Header().Set("Content-Type", "application/json")

	if r.Body != http.NoBody {
		log.Error(errInvalidBody)

		w.WriteHeader(http.StatusBadRequest)

		if err := json.NewEncoder(w).Encode(errInvalidBody); err != nil {
			log.Error(err)
		}

		return
	}

	project := vars["project"]
	instance := vars["instance"]

	dbin, err := sql.readInstance(project, instance)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)

		if err := json.NewEncoder(w).Encode("instanceDoesNotExist"); err != nil {
			log.Error(err)
		}

		return
	}

	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(dbin); err != nil {
		log.Error(err)
	}
}

func (sql *SQLAdminAPI) createEphemeralHandler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Warn(err)
		}
	}()

	authHeader := r.Header.Get("Authorization")
	if !strings.Contains(authHeader, allowedBearerToken) {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	var createRequest sqladmin.SslCertsCreateEphemeralRequest

	if err := json.NewDecoder(r.Body).Decode(&createRequest); err != nil {
		w.WriteHeader(http.StatusBadRequest)

		if _, err := w.Write([]byte(err.Error())); err != nil {
			log.Error(err)
		}

		return
	}

	certPEM, err := sql.authority.Sign(createRequest.PublicKey, pkix.Name{
		CommonName: "ephemeral-client-certificate",
	}, time.Hour)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		if _, err := w.Write([]byte(err.Error())); err != nil {
			log.Error(err)
		}

		return
	}

	respBytes, err := json.Marshal(&sqladmin.SslCert{
		Cert: certPEM,
	})
	if err != nil {
		log.Error(err)

		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(respBytes); err != nil {
		log.Error(err)
	}
}

func (sql *SQLAdminAPI) revokeCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	sql.authority.RevokeAll()

	sql.dbProxy.CloseAll()

	w.WriteHeader(http.StatusOK)

	if _, err := w.Write([]byte("OK")); err != nil {
		log.Error(err)
	}
}

func (sql *SQLAdminAPI) createInstanceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Infof("create instance called - %s %s", vars["project"], "-")
	w.Header().Set("Content-Type", "application/json")

	dbin := sqladmin.DatabaseInstance{}

	err := json.NewDecoder(r.Body).Decode(&dbin)
	if err != nil {
		log.Errorf("create instance invalid body - %s", err)
		w.WriteHeader(http.StatusBadRequest)

		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Error(err)
		}

		return
	}

	project := vars["project"]
	instance := dbin.Name

	_, err = sql.readInstance(project, instance)
	if err == nil {
		log.Infof("instance already exist - %s %s", project, dbin.Name)
		w.WriteHeader(http.StatusConflict)

		if err := json.NewEncoder(w).Encode("instanceAlreadyExists"); err != nil {
			log.Error(err)
		}

		return
	}

	if dbin.BackendType == "" {
		dbin.BackendType = "SECOND_GEN"
	}

	if len(dbin.IpAddresses) == 0 {
		dbin.IpAddresses = []*sqladmin.IpMapping{
			{
				IpAddress: util.GetMockAddress(),
				Type:      "PRIMARY",
			},
		}
	}

	if dbin.ServerCaCert == nil {
		dbin.ServerCaCert = &sqladmin.SslCert{
			Cert: sql.authority.CertPEM(),
		}
	}

	log.Infof("creating instance - %s %s", project, instance)

	dbin.State = "PENDING_CREATE"

	err = sql.writeInstance(dbin, project, instance)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Error(err)
		}

		return
	}

	defer sql.setInstanceRunning(project, instance)

	if err := sql.dbProxy.AddInstance(project, instance); err != nil {
		log.Error(err)
	}

	log.Infof("instance created - %s %s", vars["project"], dbin.Name)

	op := successOperation(project, instance, "CREATE", w.Header().Clone())

	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(op); err != nil {
		log.Error(err)
	}
}

func (sql *SQLAdminAPI) patchInstanceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Infof("patch instance called - %s %s", vars["project"], vars["instance"])
	w.Header().Set("Content-Type", "application/json")

	project := vars["project"]
	instance := vars["instance"]

	dbin, err := sql.readInstance(project, instance)
	if err != nil {
		log.Infof("instance does not exist - %s %s", project, instance)

		w.WriteHeader(http.StatusNotFound)

		return
	}

	err = json.NewDecoder(r.Body).Decode(&dbin)
	if err != nil {
		// nothing changed just ok
		w.WriteHeader(http.StatusOK)

		return
	}

	log.Infof("patching instance - %s %s", vars["project"], dbin.Name)
	dbin.State = "PENDING_UPDATE"

	err = sql.writeInstance(dbin, project, instance)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Error(err)
		}

		return
	}

	defer sql.setInstanceRunning(project, instance)

	log.Infof("instance updated - %s %s", vars["project"], dbin.Name)

	op := successOperation(project, instance, "UPDATE", w.Header().Clone())

	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(op); err != nil {
		log.Error(err)
	}
}

func (sql *SQLAdminAPI) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Infof("update user called  - %s %s", vars["project"], vars["instance"])
	w.Header().Set("Content-Type", "application/json")

	hostList, ok := r.URL.Query()["host"]
	if !ok || hostList[0] == "" {
		w.WriteHeader(http.StatusBadRequest)

		if err := json.NewEncoder(w).Encode("Missing parameter: host."); err != nil {
			log.Error(err)
		}

		return
	}

	nameList, ok := r.URL.Query()["name"]
	if !ok || nameList[0] == "" {
		w.WriteHeader(http.StatusBadRequest)

		if err := json.NewEncoder(w).Encode("Missing parameter: user."); err != nil {
			log.Error(err)
		}

		return
	}

	sqlUser := sqladmin.User{}

	err := json.NewDecoder(r.Body).Decode(&sqlUser)
	if err != nil {
		log.Errorf("user update invalid body - %s", err)

		w.WriteHeader(http.StatusBadRequest)

		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Error(err)
		}

		return
	}

	log.Infof("Request body: %v", sqlUser)

	project := vars["project"]
	instance := vars["instance"]
	username := nameList[0]
	host := hostList[0]

	log.Infof("updating user - %s %s %s %s", project, instance, username, host)

	err = sql.writeUser(sqlUser, project, instance, nameList[0], hostList[0])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Error(err)
		}

		return
	}

	op := successOperation(project, instance, "UPDATE", w.Header().Clone())

	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(op); err != nil {
		log.Error(err)
	}
}

func (sql *SQLAdminAPI) healthCheckRequestHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode("healthy"); err != nil {
		log.Error(err)
	}
}

func (sql *SQLAdminAPI) readInstance(project, instance string) (sqladmin.DatabaseInstance, error) {
	log.Infof("db reading %s - %s", project, instance)

	dbin := sqladmin.DatabaseInstance{}

	if err := sql.DB.Read(project, instance, &dbin); err != nil {
		log.Error("failed to read instance to db", err)

		return dbin, err
	}

	return dbin, nil
}

func (sql *SQLAdminAPI) writeInstance(dbin sqladmin.DatabaseInstance, project, instance string) error {
	log.Infof("db writing %s - %s", project, instance)

	err := sql.DB.Write(project, instance, dbin)
	if err != nil {
		log.Error("failed to write instance to db", err)

		return err
	}

	return nil
}

func (sql *SQLAdminAPI) setInstanceRunning(project, instance string) {
	const delay = 5

	time.Sleep(delay * time.Second)

	dbin, err := sql.readInstance(project, instance)
	if err != nil {
		log.Fatal("can not get instance state")
	}

	dbin.State = "RUNNABLE"

	err = sql.writeInstance(dbin, project, instance)
	if err != nil {
		log.Fatal("can not update instance state")
	}

	log.Infof("instance is running - %s %s", project, instance)
}

func (sql *SQLAdminAPI) writeUser(user sqladmin.User, project, instance, username, host string) error {
	rc := fmt.Sprintf("%s-%s-%s", instance, username, host)

	err := sql.DB.Write(project, rc, user)
	if err != nil {
		log.Error("failed to write user", err)

		return err
	}

	return nil
}

func successOperation(project, instance, opType string, header http.Header) sqladmin.Operation {
	return sqladmin.Operation{
		Kind:          "sql#operation",
		Status:        "PENDING",
		OperationType: opType,
		TargetId:      instance,
		TargetProject: project,
		ServerResponse: googleapi.ServerResponse{
			Header:         header,
			HTTPStatusCode: http.StatusOK,
		},
	}
}
