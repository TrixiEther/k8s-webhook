package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"encoding/json"
	"io/ioutil"
	"k8s.io/api/admission/v1beta1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/kubernetes/pkg/apis/core/v1"

	"github.com/sirupsen/logrus"
	"github.com/ghodss/yaml"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()

	// (https://github.com/kubernetes/kubernetes/issues/57982)
	defaulter = runtime.ObjectDefaulter(runtimeScheme)
)

var LOGGER = logrus.Logger{}

type WebhookServer struct {
	server        *http.Server
	coreConfig []WebhookConfigMap
}

// Webhook Server parameters
type WhSvrParameters struct {
	port           int    // webhook server port
	certFile       string // path to the x509 certificate for https
	keyFile        string // path to the x509 private key matching `CertFile`
	webhookCfgFile string // webhook core config file
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

type WebhookConfigMap struct {
    LabelKey string `json:"labelKey"`
    Value string `json:"value"`
    File string `json:"file"`
    Types []string `json:"types"`
}

type Config struct {
	Affinity    *corev1.Affinity    `yaml:"affinity"`
	NodeSelector    map[string]string    `yaml:"nodeSelector"`
	Tolerations   []corev1.Toleration   `yaml:"tolerations"`
}

const (
	admissionWebhookStatusKey = "mutated-status"
)

const (
	admissionWebhookPartStatusKey = "mutated-"
)

func addTolerations(tolerations []corev1.Toleration, basePath string) (patch []patchOperation){

    patch = append(patch, patchOperation{
        Op: "add",
        Path: basePath,
        Value: tolerations,
    })

    return patch
}

func addNodeSelector(nodeSelector map[string]string, basePath string) (patch []patchOperation) {

    patch = append(patch, patchOperation{
        Op: "add",
        Path: basePath,
        Value: nodeSelector,
    })

    return patch
}

func addAffinity(affinity *corev1.Affinity, basePath string) (patch []patchOperation) {

    patch = append(patch, patchOperation{
        Op:    "add",
        Path:  basePath,
        Value: affinity,
    })

	return patch
}

func addLabel(added map[string]string, basePath string) (patch []patchOperation) {
	for key, value := range added {
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  basePath + key,
			Value: value,
		})
	}
	return patch
}

// create mutation patch for resoures
func createPatch(pod *corev1.Pod, coreConfig []WebhookConfigMap) ([]byte, error) {

	var patch []patchOperation
	var patchNeeded = false
	var patchFile = ""
	var patchFileNum = 0

	// we find out whether it is necessary to patch pod
	for i, configPart := range coreConfig {
	    for key, value := range pod.ObjectMeta.Labels {
	        if ( key == configPart.LabelKey && value == configPart.Value ) {
	            logrus.Infof("Pod with label Key=%v, Value=%v will be patched", key, value)
	            patchNeeded = true
	            patchFile = configPart.File
	            patchFileNum = i
	        }
	    }
	}

	if ( patchNeeded == true ) {
        labels := map[string]string{admissionWebhookStatusKey: "injected"}
        patch = append(patch, addLabel(labels, "/metadata/labels/")...)

        var filePath = "/configs/inject/" + patchFile

        for _, patchType := range coreConfig[patchFileNum].Types {

            switch patchType {
                case "affinity":

                    labelsPart := map[string]string{admissionWebhookPartStatusKey + patchType : "ok"}
                    patch = append(patch, addLabel(labelsPart, "/metadata/labels/")...)

                    affinityConfig, err := loadConfig(filePath)
                    if err != nil {
                        logrus.Errorf("Failed to load config file: %v", err)
                        break
                    }
                    patch = append(patch, addAffinity(affinityConfig.Affinity, "/spec/affinity")...)

                case "nodeSelector":

                    labelsPart := map[string]string{admissionWebhookPartStatusKey + patchType : "ok"}
                    patch = append(patch, addLabel(labelsPart, "/metadata/labels/")...)

                    nodeSelectorConfig, err := loadConfig(filePath)
                    if err != nil {
                        logrus.Errorf("Failed to load config file: %v", err)
                        break
                    }
                    patch = append(patch, addNodeSelector(nodeSelectorConfig.NodeSelector, "/spec/nodeSelector")...)

                case "tolerations":

                    labelsPart := map[string]string{admissionWebhookPartStatusKey + patchType : "ok"}
                    patch = append(patch, addLabel(labelsPart, "/metadata/labels/")...)

                    tolerationsConfig, err := loadConfig(filePath)
                    if err != nil {
                        logrus.Errorf("Failed to load config file: %v", err)
                        break
                    }
                    patch = append(patch, addTolerations(tolerationsConfig.Tolerations, "/spec/tolerations")...)

                default:
                    logrus.Infof("Patch type=%v not supported", patchType)
            }
        }
	}

	return json.Marshal(patch)

}

// main mutation process
func (whsvr *WebhookServer) mutate(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := ar.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		logrus.Errorf("Could not unmarshal raw object: %v", err)
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	logrus.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo)
	
	patchBytes, err := createPatch(&pod, whsvr.coreConfig)

	if err != nil {
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	logrus.Infof("AdmissionResponse: patch=%v\n", string(patchBytes))
	return &v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

// Serve method for webhook server
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		logrus.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		logrus.Error("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		logrus.Errorf("Can't decode body: %v", err)
		admissionResponse = &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = whsvr.mutate(&ar)
	}

	admissionReview := v1beta1.AdmissionReview{}
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		logrus.Errorf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	logrus.Infof("Ready to write reponse ...")
	if _, err := w.Write(resp); err != nil {
		logrus.Errorf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}

func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionregistrationv1beta1.AddToScheme(runtimeScheme)
	// defaulting with webhooks:
	// https://github.com/kubernetes/kubernetes/issues/57982
	_ = v1.AddToScheme(runtimeScheme)

    logrus.SetFormatter(&logrus.TextFormatter{
        TimestampFormat: "2006-01-02T15:04:05.000",
        FullTimestamp: true,
    })

    logrus.Infof("Successfully initialized")
}

func loadConfig(configFile string) (*Config, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func loadWebhookConfig(configFile string) ([]WebhookConfigMap, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var cfg []WebhookConfigMap
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func main() {
	var parameters WhSvrParameters

	// get command line parameters
	flag.IntVar(&parameters.port, "port", 8443, "Webhook server port.")
	flag.StringVar(&parameters.certFile, "tlsCertFile", "/certs/cert.pem", "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&parameters.keyFile, "tlsKeyFile", "/certs/key.pem", "File containing the x509 private key to --tlsCertFile.")
	flag.StringVar(&parameters.webhookCfgFile, "webhookCfgFile", "/configs/core/mapconfigs.yaml", "File containing the webhook configuration.")
	flag.Parse()

    var webhookCoreConfig []WebhookConfigMap
	webhookCoreConfig, err := loadWebhookConfig(parameters.webhookCfgFile)
    if err != nil {
        logrus.Errorf("Failed to load webhook configuration: %v", err)
    }

    for _, v := range webhookCoreConfig {
        logrus.Infof(v.Value)
    }

	pair, err := tls.LoadX509KeyPair(parameters.certFile, parameters.keyFile)
	if err != nil {
		logrus.Errorf("Failed to load key pair: %v", err)
	}

	whsvr := &WebhookServer{
	    coreConfig: webhookCoreConfig,
		server: &http.Server{
			Addr:      fmt.Sprintf(":%v", parameters.port),
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}},
		},
	}

	// define http server and server handler
	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", whsvr.serve)
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from GoLang!")
	})
	whsvr.server.Handler = mux

	// start webhook server in new rountine
	go func() {
		if err := whsvr.server.ListenAndServeTLS("", ""); err != nil {
			logrus.Errorf("Failed to listen and serve webhook server: %v", err)
		}
	}()

	// listening OS shutdown singal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	logrus.Infof("Got OS shutdown signal, shutting down webhook server gracefully...")
	whsvr.server.Shutdown(context.Background())
}
