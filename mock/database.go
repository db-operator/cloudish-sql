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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	"git.kci.rocks/DevOps/cloudish-sql/pubkey"
	"git.kci.rocks/DevOps/cloudish-sql/util"
	log "github.com/sirupsen/logrus"
)

// DatabaseProxy is a mutual tls proxy for the end-to-end test suite.
type DatabaseProxy struct {
	ctx         context.Context
	ctxCancel   context.CancelFunc
	ctxMu       sync.Mutex
	authority   *pubkey.Authority
	serverKey   *rsa.PrivateKey
	dbAddress   string
	serverCerts map[string]*x509.Certificate
}

// ErrRevokedCertificate is returned when a certificate has been revoked.
var ErrRevokedCertificate = errors.New("certificate has been revoked")

// ErrUnrecognizedTLSHost is returned when a client connects with the wrong hostname.
var ErrUnrecognizedTLSHost = errors.New("unrecognized tls host")

// NewDatabaseProxy constructs a new mutual tls proxy for the supplied database.
func NewDatabaseProxy(authority *pubkey.Authority, dbAddress string) (*DatabaseProxy, error) {
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	ctx, ctxCancel := context.WithCancel(context.Background())

	return &DatabaseProxy{
		ctx:         ctx,
		ctxCancel:   ctxCancel,
		authority:   authority,
		serverKey:   serverKey,
		dbAddress:   dbAddress,
		serverCerts: make(map[string]*x509.Certificate),
	}, nil
}

// Run starts the database mutual tls proxy.
func (dp *DatabaseProxy) Run() error {
	caCert, err := pubkey.ParseCertificate(dp.authority.CertPEM())
	if err != nil {
		return err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			var serverCert *x509.Certificate

			// If only a single instance, serve up the certificate for all hostnames.
			if len(dp.serverCerts) == 1 {
				log.Info("Found a single server certificate")

				databases := reflect.ValueOf(dp.serverCerts).MapKeys()
				serverCert = dp.serverCerts[databases[0].String()]
			} else {
				var ok bool
				serverCert, ok = dp.serverCerts[info.ServerName]
				if !ok {
					return nil, ErrUnrecognizedTLSHost
				}
			}

			serverCertChain := []tls.Certificate{
				{Certificate: [][]byte{serverCert.Raw}, PrivateKey: dp.serverKey},
				{Certificate: [][]byte{caCert.Raw}},
			}

			return &tls.Config{
				MinVersion:   tls.VersionTLS13,
				ClientCAs:    caCertPool,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				Certificates: serverCertChain,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					log.Info("Verifying peer certificate")

					for _, verifiedChain := range verifiedChains {
						for _, cert := range verifiedChain {
							if dp.authority.IsRevoked(cert) {
								return ErrRevokedCertificate
							}
						}
					}

					log.Info("Successfully verified peer certificate")

					return nil
				},
			}, nil
		},
	}

	tlsConn, err := tls.Listen("tcp", ":3307", tlsConfig) /* #nosec. */
	if err != nil {
		return err
	}

	defer func() {
		if err := tlsConn.Close(); err != nil {
			log.Warn(err)
		}
	}()

	for {
		conn, err := tlsConn.Accept()
		if err != nil {
			log.Error(err)

			continue
		}

		go func() {
			dbConn, err := net.Dial("tcp", dp.dbAddress)
			if err != nil {
				log.Error(err)
			}

			dp.ctxMu.Lock()

			connCtx, connCancel := context.WithCancel(dp.ctx)

			dp.ctxMu.Unlock()

			cancellableConn := util.MakeCancellable(connCtx, conn)

			cancellableDBConn := util.MakeCancellable(connCtx, dbConn)

			var wg sync.WaitGroup

			wg.Add(2)

			go func() {
				if _, err := io.Copy(cancellableDBConn, cancellableConn); err != nil {
					log.Warn(err)
				}

				if !errors.Is(err, context.Canceled) {
					connCancel()
				}

				wg.Done()
			}()

			go func() {
				if _, err := io.Copy(cancellableConn, cancellableDBConn); err != nil {
					log.Warn(err)
				}

				if !errors.Is(err, context.Canceled) {
					connCancel()
				}

				wg.Done()
			}()

			wg.Wait()

			log.Info("Closing connection")

			if err := cancellableDBConn.Close(); err != nil {
				log.Warn(err)
			}

			if err := cancellableConn.Close(); err != nil {
				log.Warn(err)
			}
		}()
	}
}

func (dp *DatabaseProxy) AddInstance(project, instance string) error {
	pubKeyPEM, err := pubkey.EncodePublicKey(&dp.serverKey.PublicKey)
	if err != nil {
		return err
	}

	database := instance

	databaseNameComponents := strings.Split(instance, "~")
	if len(databaseNameComponents) > 1 {
		database = databaseNameComponents[1]
	}

	projectName := fmt.Sprintf("%s:%s", project, database)

	serverCertPEM, err := dp.authority.Sign(pubKeyPEM, pkix.Name{
		CommonName: projectName,
	}, time.Hour)
	if err != nil {
		return err
	}

	serverCert, err := pubkey.ParseCertificate(serverCertPEM)
	if err != nil {
		return err
	}

	dp.serverCerts[instance] = serverCert

	return nil
}

// CloseAll closes all existing connections.
func (dp *DatabaseProxy) CloseAll() {
	log.Info("Closing all established connections")

	dp.ctxMu.Lock()
	defer dp.ctxMu.Unlock()

	dp.ctxCancel()

	dp.ctx, dp.ctxCancel = context.WithCancel(context.Background())
}
