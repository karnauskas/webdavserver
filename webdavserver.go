// command webdavserver provides access to given directory via WebDAV protocol
package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/artyom/autoflags"
	"golang.org/x/net/webdav"

	spew "github.com/davecgh/go-spew/spew"
	logrus "github.com/sirupsen/logrus"
)

func main() {
	p := struct {
		Dir    string `flag:"dir,directory to serve"`
		Addr   string `flag:"addr,address to listen"`
		Auth   string `flag:"auth,basic auth credentials in user:password format (or set WEBDAV_AUTH env)"`
		TLSKey string `flag:"key,TLS private key for secure connection"`
		TLSCrt string `flag:"crt,TLS public key for secure conneciton"`
		Log    bool   `flag:"debug,Log requests"`
	}{
		Dir:    ".",
		Addr:   "127.0.0.1:8080",
		Auth:   os.Getenv("WEBDAV_AUTH"),
		TLSKey: "",
		TLSCrt: "",
		Log:    false,
	}
	autoflags.Parse(&p)
	log.Fatal(serve(p.Dir, p.Addr, p.Auth, p.TLSCrt, p.TLSKey, p.Log))
}

type logger struct {
	l *logrus.Logger
}

func (self *logger) Log(r *http.Request, e error) {

	switch r.Method {
	case "PROPFIND":
	case "GET":
		self.l.Infof("%s: %s %s", r.RemoteAddr, r.Method, r.RequestURI)
	case "MOVE":
		u, err := url.Parse(r.Header["Destination"][0])
		if err != nil {
			self.l.Errorf("%s: %s %s : %s", r.RemoteAddr, r.Method, r.RequestURI, e)
			return
		}
		self.l.Infof("%s: %s %s => %s", r.RemoteAddr, r.Method, r.RequestURI, u.Path)
	case "COPY":
		u, err := url.Parse(r.Header["Destination"][0])
		if err != nil {
			self.l.Errorf("%s: %s %s : %s", r.RemoteAddr, r.Method, r.RequestURI, e)
			return
		}
		self.l.Infof("%s: %s %s => %s", r.RemoteAddr, r.Method, r.RequestURI, u.Path)
	case "DELETE":
		self.l.Infof("%s: %s %s", r.RemoteAddr, r.Method, r.RequestURI)
	case "MKCOL":
		self.l.Infof("%s: %s %s", r.RemoteAddr, "MKDIR", r.RequestURI)
	case "PUT":
		self.l.Infof("%s: %s %s %d", r.RemoteAddr, r.Method, r.RequestURI, r.ContentLength)
	default:
		spew.Dump(r)
		self.l.Infof("%s: %s %s", r.RemoteAddr, r.Method, r.RequestURI)
	}

	if e != nil {
		self.l.Errorf("%s: %s", r.RemoteAddr, e)
	}
}

func serve(dir, addr, auth, tlscrt, tlskey string, log bool) error {
	var handler http.Handler
	webdavHandler := &webdav.Handler{
		FileSystem: webdav.Dir(dir),
		LockSystem: webdav.NewMemLS(),
	}
	if log {
		l := &logger{l: logrus.New()}
		webdavHandler.Logger = l.Log
	}
	handler = webdavHandler
	if auth != "" {
		fields := strings.SplitN(auth, ":", 2)
		if len(fields) != 2 {
			return errors.New("invalid auth format (want user:password)")
		}
		want := sha256.Sum256([]byte(auth))
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, p, ok := r.BasicAuth()
			got := sha256.Sum256([]byte(u + ":" + p))
			if !ok || subtle.ConstantTimeCompare(want[:], got[:]) == 0 {
				w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			webdavHandler.ServeHTTP(w, r)
		})
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	if tlscrt != "" && tlskey != "" {
		return server.ListenAndServeTLS(tlscrt, tlskey)
	} else {
		return server.ListenAndServe()
	}
}
