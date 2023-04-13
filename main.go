package main

import (
	"crypto/x509/pkix"
	"os"
	"time"

	"github.com/db-operator/cloudish-sql/mock"
	"github.com/db-operator/cloudish-sql/pubkey"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

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

func main() {
	// set loglevel
	setLogLevel()

	log.SetFormatter(&log.JSONFormatter{})

	if term.IsTerminal(int(os.Stdout.Fd())) {
		log.SetFormatter(&log.TextFormatter{})
	}

	if err := execute(); err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Fatal("Failed to execute command")
	}
}

func setLogLevel() {
	level := os.Getenv("LOG_LEVEL")

	logLevel, err := log.ParseLevel(level)
	if err != nil {
		log.Printf("can not parse loglevel")
		logLevel = log.InfoLevel
	}

	log.SetLevel(logLevel)
}

func execute() error {
	rootCmd := &cobra.Command{
		Use:   "cloudish-sql",
		Short: "Run a local Google managed database mock (for testing)",
		RunE:  startMock,
	}

	rootCmd.Flags().String("db-address", "", "Address of the database for which to proxy")
	rootCmd.Flags().Int("api-port", 8080, "Port on which to serve the mocked sqladmin API")

	if err := rootCmd.MarkFlagRequired("db-address"); err != nil {
		return err
	}

	return rootCmd.Execute()
}

func startMock(cmd *cobra.Command, args []string) error {
	dbAddress, err := cmd.Flags().GetString("db-address")
	if err != nil {
		return err
	}

	apiPort, err := cmd.Flags().GetInt("api-port")
	if err != nil {
		return err
	}

	authority, err := pubkey.NewAuthority(pkix.Name{
		CommonName: "Mock CA",
	}, time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	dbProxy, err := mock.NewDatabaseProxy(authority, dbAddress)
	if err != nil {
		log.Fatal(err)
	}

	sqlAdminAPI, err := mock.NewSQLAdminAPI(dbProxy, authority, apiPort)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		if err := dbProxy.Run(); err != nil {
			log.Fatal(err)
		}
	}()

	if err := sqlAdminAPI.Run(); err != nil {
		log.Fatal(err)
	}

	return nil
}
