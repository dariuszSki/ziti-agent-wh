package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"
	admissionv1 "k8s.io/api/admission/v1"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
)

var (
	certFile         string
	keyFile          string
	port             int
	sidecarImage     string
	sidecarName      string
	zitiCtrlAddress  string
	zitiCtrlUsername string
	zitiCtrlPassword string
	runtimeScheme    = runtime.NewScheme()
)

var CmdWebhook = &cobra.Command{
	Use:   "webhook",
	Short: "Starts a HTTP server, useful for testing MutatingAdmissionWebhook",
	Long: `Starts a HTTP server, useful for testing MutatingAdmissionWebhook.
After deploying it to Kubernetes cluster, the Administrator needs to create a MutatingWebhookConfiguration
in the Kubernetes cluster to register remote webhook admission controllers.`,
	Args: cobra.MaximumNArgs(0),
	Run:  webhook,
}

func init() {
	CmdWebhook.Flags().StringVar(&certFile, "tls-cert-file", "",
		"File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert).")
	CmdWebhook.Flags().StringVar(&keyFile, "tls-private-key-file", "",
		"File containing the default x509 private key matching --tls-cert-file.")
	CmdWebhook.Flags().IntVar(&port, "port", 9443,
		"Secure port that the webhook listens on")
	CmdWebhook.Flags().StringVar(&sidecarImage, "sidecar-image", "openziti/ziti-tunnel",
		"Image to be used as the injected sidecar")
	CmdWebhook.Flags().StringVar(&sidecarName, "sidecar-name", "ziti-tunnel",
		"ContainerName to be used for the injected sidecar")
	CmdWebhook.Flags().StringVar(&zitiCtrlAddress, "ziti-ctrl-addr", "",
		"Ziti Controller IP Address / FQDN")
	CmdWebhook.Flags().StringVar(&zitiCtrlUsername, "ziti-ctrl-un", "",
		"Ziti Controller Username")
	CmdWebhook.Flags().StringVar(&zitiCtrlPassword, "ziti-ctrl-pw", "",
		"Ziti Controller Password")

	/*
		AdmissionReview is registered for version admission.k8s.io/v1 or admission.k8s.io/v1beta1
		in scheme "https://github.com/kubernetes/apimachinery/blob/master/pkg/runtime/scheme.go:100"
	*/
	addToScheme(scheme)
}

// admitv1beta1Func handles a v1beta1 admission
type admitv1beta1Func func(admissionv1beta1.AdmissionReview) *admissionv1beta1.AdmissionResponse

// admitv1Func handles a v1 admission
type admitv1Func func(admissionv1.AdmissionReview) *admissionv1.AdmissionResponse

// admitHandler is a handler, for both validators and mutators, that supports multiple admission review versions
type admitHandler struct {
	admissionv1beta1 admitv1beta1Func
	admissionv1      admitv1Func
}

func newDelegateToV1AdmitHandler(f admitv1Func) admitHandler {
	return admitHandler{
		admissionv1beta1: delegateV1beta1AdmitToV1(f),
		admissionv1:      f,
	}
}

func delegateV1beta1AdmitToV1(f admitv1Func) admitv1beta1Func {
	return func(review admissionv1beta1.AdmissionReview) *admissionv1beta1.AdmissionResponse {
		in := admissionv1.AdmissionReview{Request: convertAdmissionRequestToV1(review.Request)}
		out := f(in)
		return convertAdmissionResponseToV1beta1(out)
	}
}

// serve handles the http portion of a request prior to handing to an admit function
func serve(w http.ResponseWriter, r *http.Request, admit admitHandler) {
	var body []byte
	if r.Body != nil {
		if data, err := io.ReadAll(r.Body); err == nil {
			body = data
		}
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		klog.Errorf("contentType=%s, expect application/json", contentType)
		return
	}

	obj, gvk, err := deserializer.Decode(body, nil, nil)
	if err != nil {
		msg := fmt.Sprintf("Request could not be decoded: %v", err)
		klog.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	var responseObj runtime.Object
	switch *gvk {
	case admissionv1beta1.SchemeGroupVersion.WithKind("AdmissionReview"):
		requestedAdmissionReview, ok := obj.(*admissionv1beta1.AdmissionReview)
		if !ok {
			klog.Errorf("Expected v1beta1.AdmissionReview but got: %T", obj)
			return
		}
		responseAdmissionReview := &admissionv1beta1.AdmissionReview{}
		responseAdmissionReview.SetGroupVersionKind(*gvk)
		responseAdmissionReview.Response = admit.admissionv1beta1(*requestedAdmissionReview)
		responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		responseObj = responseAdmissionReview

		// klog.Infof(fmt.Sprintf("Admission Request v1 - Operation: %s", requestedAdmissionReview.Request.Operation))

	case admissionv1.SchemeGroupVersion.WithKind("AdmissionReview"):
		requestedAdmissionReview, ok := obj.(*admissionv1.AdmissionReview)
		if !ok {
			klog.Errorf("Expected v1.AdmissionReview but got: %T", obj)
			return
		}
		responseAdmissionReview := &admissionv1.AdmissionReview{}
		responseAdmissionReview.SetGroupVersionKind(*gvk)
		responseAdmissionReview.Response = admit.admissionv1(*requestedAdmissionReview)
		responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		responseObj = responseAdmissionReview

		// klog.Infof(fmt.Sprintf("Admission Request v1beta1 - Operation: %s", requestedAdmissionReview.Request.Operation))

	default:
		msg := fmt.Sprintf("Unsupported group version kind: %v", gvk)
		klog.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	respBytes, err := json.Marshal(responseObj)
	if err != nil {
		klog.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(respBytes); err != nil {
		klog.Error(err)
	}
}

func serveZitiTunnelSC(w http.ResponseWriter, r *http.Request) {
	serve(w, r, newDelegateToV1AdmitHandler(zitiTunnel))
}

func webhook(cmd *cobra.Command, args []string) {

	config := Config{
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	http.HandleFunc("/ziti-tunnel", serveZitiTunnelSC)
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		TLSConfig: configTLS(config),
	}
	err := server.ListenAndServeTLS("", "")
	if err != nil {
		panic(err)
	}
}
