package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"iter"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	gonanoid "github.com/matoous/go-nanoid/v2"
)

var logger *slog.Logger = createLogger()

func main() {
	HOST := getEnvOrFileWithFallback("HOST", "0.0.0.0")
	PORT, err := strconv.ParseInt(getEnvOrFileWithFallback("PORT", "8080"), 10, 16)
	if err != nil {
		logger.Error("Invalid port", "error", err)
		panic(err)
	}

	modProxy, err := createModProxy()
	if err != nil {
		logger.Error("Error creating mod proxy", "error", err)
		panic(err)
	}

	route := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		logger := logger.With("requestId", req.Context().Value("requestId"))
		logger.Info("new request", "method", req.Method, "uri", req.RequestURI, "headers", req.Header, "ip", req.RemoteAddr)

		reqStart := time.Now()
		modProxy.ServeHTTP(rw, req)
		logger.Debug("got response", "took", time.Since(reqStart).String())
	})
	handler := middlewareAddRequestId(route)

	listenOn := fmt.Sprintf("%s:%d", HOST, PORT)
	logger.Debug("Starting server", "bindAddr", listenOn)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := http.ListenAndServe(listenOn, handler)
		if err != nil {
			logger.Error("Error starting server", "error", err)
			panic(err)
		}
	}()

	logger.Info("Server started", "listeningOn", fmt.Sprintf("http://%s", listenOn))
	wg.Wait()
}

type reqHandler struct {
	handler func(*http.Request)
}

var reqHandlerFactories = [](func(string) (*reqHandler, error)){
	func(envName string) (*reqHandler, error) {
		cleanName, ok := strings.CutPrefix(envName, "PROXY_HEADER_ADD_")
		if !ok {
			return nil, nil
		}
		cleanName = strings.TrimSuffix(cleanName, "_FILE")

		headerValue, err := getHeaderValue(envName)
		if err != nil {
			return nil, err
		}

		logger.Debug("Adding handler to set header if not exists", "name", cleanName, "value", headerValue)

		return &reqHandler{
			handler: func(r *http.Request) {
				if r.Header.Get(cleanName) == "" {
					r.Header.Set(cleanName, headerValue)
				}
			},
		}, nil
	},

	func(envName string) (*reqHandler, error) {
		cleanName, ok := strings.CutPrefix(envName, "PROXY_HEADER_SET_")
		if !ok {
			return nil, nil
		}
		cleanName = strings.TrimSuffix(cleanName, "_FILE")

		headerValue, err := getHeaderValue(envName)
		if err != nil {
			return nil, err
		}

		logger.Debug("Adding handler to set header", "name", cleanName, "value", headerValue)

		return &reqHandler{
			handler: func(r *http.Request) {
				r.Header.Set(cleanName, headerValue)
			},
		}, nil
	},

	func(envName string) (*reqHandler, error) {
		cleanName, ok := strings.CutPrefix(envName, "PROXY_HEADER_APPEND_")
		if !ok {
			return nil, nil
		}
		cleanName = strings.TrimSuffix(cleanName, "_FILE")

		headerValue, err := getHeaderValue(envName)
		if err != nil {
			return nil, err
		}

		logger.Debug("Adding handler to append header", "name", cleanName, "value", headerValue)

		return &reqHandler{
			handler: func(r *http.Request) {
				r.Header.Add(cleanName, headerValue)
			},
		}, nil
	},

	func(envName string) (*reqHandler, error) {
		cleanName, ok := strings.CutPrefix(envName, "PROXY_HEADER_REMOVE_")
		if !ok {
			return nil, nil
		}

		logger.Debug("Adding handler to remove header", "name", cleanName)

		return &reqHandler{
			handler: func(r *http.Request) {
				r.Header.Del(cleanName)
			},
		}, nil
	},
}

func getHeaderValue(envName string) (string, error) {
	headerValue, err := getEnvOrFile(envName)

	if err != nil {
		logger.Error("Error finding header value", "name", envName, "error", err)
		return "", err
	}

	if headerValue == nil || *headerValue == "" {
		logger.Error("Header value is required", "name", envName)
		return "", fmt.Errorf("Header value is required for %s", envName)
	}

	return *headerValue, nil
}

func createReqHandlers() ([]reqHandler, error) {
	reqHandlers := make([]reqHandler, 0)
	for _, envVarPair := range os.Environ() {
		next, stop := iter.Pull(strings.SplitSeq(envVarPair, "="))
		defer stop()
		envName, ok := next()
		if !ok {
			continue
		}

		for _, factory := range reqHandlerFactories {
			handler, err := factory(envName)
			if err != nil {
				return nil, err
			}

			if handler != nil {
				reqHandlers = append(reqHandlers, *handler)
			}
		}
	}

	return reqHandlers, nil
}

func createModProxy() (*httputil.ReverseProxy, error) {
	proxyUrlStr, err := getEnvOrFile("PROXY_TO")
	if err != nil {
		return nil, err
	}
	if proxyUrlStr == nil || *proxyUrlStr == "" {
		return nil, fmt.Errorf("PROXY_TO is required")
	}
	logger.Debug("Proxying to URL", "url", proxyUrlStr)
	proxyUrl, err := url.Parse(*proxyUrlStr)
	if err != nil {
		return nil, err
	}

	reqHandlers, err := createReqHandlers()
	if err != nil {
		return nil, err
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	proxy := httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetXForwarded()
			r.SetURL(proxyUrl)
			for _, handler := range reqHandlers {
				handler.handler(r.Out)
			}
		},
	}

	return &proxy, nil
}

func middlewareAddRequestId(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := gonanoid.New()
		if err != nil {
			logger.Error("Error generating request id", "error", err)
		} else {
			w.Header().Set("X-Mod-Proxy-Request-Id", id)
			r = r.WithContext(context.WithValue(r.Context(), "requestId", id))
		}
		next.ServeHTTP(w, r)
	})
}

func createLogger() *slog.Logger {
	opts := slog.HandlerOptions{}

	logLevel := getEnvOrFileWithFallback("LOG_LEVEL", "info")

	switch strings.ToUpper(logLevel) {
	case "TRACE":
		fallthrough
	case "DEBUG":
		opts.Level = slog.LevelDebug
	case "WARN":
		opts.Level = slog.LevelWarn
	case "ERROR":
		opts.Level = slog.LevelError
	default:
		opts.Level = slog.LevelInfo
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, &opts))
}

func getEnvOrFile(key string) (*string, error) {
	value, ok := os.LookupEnv(key)
	if !ok {
		return nil, nil
	}

	if !strings.HasSuffix(key, "_FILE") {
		return &value, nil
	}

	contentsB, err := os.ReadFile(value)
	if err != nil {
		return nil, err
	}
	contents := string(contentsB)
	contents = strings.TrimSpace(contents)

	return &contents, nil
}

func getEnvOrFileWithFallback(key, fallback string) string {
	value, err := getEnvOrFile(key)
	if err != nil {
		return fallback
	}

	if value == nil {
		return fallback
	}

	return *value
}
