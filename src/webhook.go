package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"
	"gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

var (
	certFile string
	keyFile  string
)

// Define config options
type SidecarConfig struct {
	Image string `json:"image"`
	Name  string `json:"name"`
}
type TlsConfig struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

func configTLS(config TlsConfig) *tls.Config {
	sCert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		klog.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{sCert},
	}
}

var CmdWebhook = &cobra.Command{
	Use:   "webhook",
	Short: "Starts a HTTP server, useful for testing MutatingAdmissionWebhook and ValidatingAdmissionWebhook",
	Long: `Starts a HTTP server, useful for testing MutatingAdmissionWebhook and ValidatingAdmissionWebhook.
After deploying it to Kubernetes cluster, the Administrator needs to create a ValidatingWebhookConfiguration
in the Kubernetes cluster to register remote webhook admission controllers.`,
	Args: cobra.MaximumNArgs(0),
	Run:  webhook,
}

func init() {
	CmdWebhook.Flags().StringVar(&certFile, "tls-cert-file", "",
		"File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert).")
	CmdWebhook.Flags().StringVar(&keyFile, "tls-private-key-file", "",
		"File containing the default x509 private key matching --tls-cert-file.")
}

func createPatch(currentPodSpec metav1.ObjectMeta, newPodSpec corev1.PodSpec) ([]byte, error) {
	// Generate a JSON patch representing the changes to the Pod spec
	patched, err := json.Marshal(newPodSpec)
	if err != nil {
		return nil, err
	}
	klog.Infof("Generated a JSON patch representing the changes to the Pod spec")
	unpatched, err := json.Marshal(currentPodSpec)
	if err != nil {
		return nil, err
	}
	p, err := jsonpatch.CreatePatch(unpatched, patched)
	if err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

func serve(w http.ResponseWriter, r *http.Request) {

	// Initilizes the sidecar container configs
	sidecarConfig := SidecarConfig{
		Image: "openziti/ziti-tunnel:latest",
		Name:  "zt-tunnel-proxy",
	}

	// Read the AdmissionReview request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// verify the content type is application/json
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		klog.Errorf("contentType=%s, expect application/json", contentType)
		return
	}

	// Define AdmissionReview struct
	var review admissionv1.AdmissionReview

	// klog.Infof("ReadAll")
	// Unmarshal the request body into AdmissionReview struct
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, "Failed to unmarshal request body", http.StatusBadRequest)
		return
	}

	// klog.Infof("Kind: ", review.Kind)
	// klog.Infof("API Version: ", review.APIVersion)
	// klog.Infof("Request UID: ", review.Request.UID)
	// klog.Infof("Request Kind: ", review.Request.Kind)
	// klog.Infof("Request Resource: ", review.Request.Resource)
	// klog.Infof("Request Object Name: ", review.Request.Name)
	// klog.Infof("Request Namespace: ", review.Request.Namespace)
	// klog.Infof("Request Operation: ", review.Request.Operation)
	// klog.Infof("Request Type: ", review.Request.Kind.Kind)
	// klog.Infof("Request Group: ", review.Request.Kind.Group)
	// Check if request is for Pod creation
	if review.Request.Kind.Kind != "Pod" {
		review.Response = &admissionv1.AdmissionResponse{
			UID:     review.Request.UID,
			Allowed: true,
		}
		response, err := json.Marshal(review)
		if err != nil {
			http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
			return
		}

		if _, err := w.Write(response); err != nil {
			http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
		}
		klog.Infof("Returned Response for all other than Pod Mutation")
		klog.Infof("Returned Response UID for all other than Pod Mutation: ", review.Response.UID)
		klog.Infof("Request Operation for Returned all other than Pod Mutation: ", review.Request.Operation)
		return
	}

	// klog.Infof(fmt.Sprintf("handling request: %s", body))

	// Extract the Pod object from the request
	pod := &corev1.Pod{}
	if err := json.Unmarshal(review.Request.Object.Raw, pod); err != nil {
		http.Error(w, "Failed to unmarshal pod object", http.StatusBadRequest)
		return
	}

	// Inject the sidecar container into the Pod spec
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name:  sidecarConfig.Name,
		Image: sidecarConfig.Image,
	})
	klog.Infof("Injected the sidecar container into the Pod spec")
	// Create the AdmissionReview response with the mutated Pod
	// patch, err := createPatch(pod.ObjectMeta, pod.Spec)
	// if err != nil {
	// 	http.Error(w, "Failed to create patch", http.StatusInternalServerError)
	// 	return
	// }
	klog.Infof("Created the AdmissionReview response with the mutated Pod spec")
	review.Response = &admissionv1.AdmissionResponse{
		UID:     review.Request.UID,
		Allowed: true,
		// Patch:   patch,
		// PatchType: func() *admissionv1.PatchType {
		// 	pt := admissionv1.PatchTypeJSONPatch
		// 	return &pt
		// }(),
	}

	// Marshal the response and send it back to the API server
	response, err := json.Marshal(review)
	if err != nil {
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}

	if _, err := w.Write(response); err != nil {
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
	klog.Infof("Returned Response for Pod Mutation")
	klog.Infof("Returned Response UID for Pod Mutation: ", review.Response.UID)
	klog.Infof("Request Operation for Returned Pod Mutation: ", review.Request.Operation)
	return
}

func serveMutatePods(w http.ResponseWriter, r *http.Request) {
	serve(w, r)
}

func webhook(cmd *cobra.Command, args []string) {

	tlsConfig := TlsConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	http.HandleFunc("/mutating-pods", serveMutatePods)
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", 8443),
		TLSConfig: configTLS(tlsConfig),
	}
	err := server.ListenAndServeTLS("", "")
	if err != nil {
		panic(err)
	}
}
