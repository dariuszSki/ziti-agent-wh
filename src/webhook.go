package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"
	admissionv1 "k8s.io/api/admission/v1"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/klog/v2"
)

var (
	certFile      string
	keyFile       string
	port          int
	sidecarImage  string
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
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
	CmdWebhook.Flags().StringVar(&sidecarImage, "sidecar-image", "",
		"Image to be used as the injected sidecar")

	// AdmissionReview is registered for version admission.k8s.io/v1 or admission.k8s.io/v1beta1 in scheme "pkg/runtime/scheme.go:100"
	_ = admissionv1.AddToScheme(runtimeScheme)
	_ = admissionv1beta1.AddToScheme(runtimeScheme)
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

// func createPatch(currentPodSpec metav1.ObjectMeta, newPodSpec corev1.PodSpec) ([]byte, error) {
// 	// Generate a JSON patch representing the changes to the Pod spec
// 	patched, err := json.Marshal(newPodSpec)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// klog.Infof("Generated a JSON patch representing the changes to the Pod spec")
// 	unpatched, err := json.Marshal(currentPodSpec)
// 	if err != nil {
// 		return nil, err
// 	}
// 	p, err := jsonpatch.CreatePatch(unpatched, patched)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return json.Marshal(p)
// }

// serve handles the http portion of a request prior to handing to an admit
// function
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

	// klog.Info(fmt.Sprintf("handling request: %s", body))
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

		if requestedAdmissionReview.Request.Kind.Kind == "Pod" {
			klog.Infof(fmt.Sprintf("Admission Request v1 - Operation: %s", requestedAdmissionReview.Request.Operation))
			pod := &corev1.Pod{}
			if err := json.Unmarshal(requestedAdmissionReview.Request.Object.Raw, pod); err != nil {
				http.Error(w, "Failed to unmarshal pod object", http.StatusBadRequest)
				return
			}
			klog.Infof(fmt.Sprintf("Admission Request - Type: %s", pod.Kind))
			klog.Infof(fmt.Sprintf("Admission Request - POD Name: %s", pod.ObjectMeta.Name))
			klog.Infof(fmt.Sprintf("Admission Request - POD Status: %s", pod.Status.Phase))
			for i := 0; i < len(pod.Status.ContainerStatuses); i++ {
				klog.Infof(fmt.Sprintf("Admission Request - Container Name: %s", pod.Status.ContainerStatuses[i].Name))
				klog.Infof(fmt.Sprintf("Admission Request - Container State Running: %s", pod.Status.ContainerStatuses[i].State.Running))
				klog.Infof(fmt.Sprintf("Admission Request - Container State Waiting: %s", pod.Status.ContainerStatuses[i].State.Waiting))
				klog.Infof(fmt.Sprintf("Admission Request - Container State Terminated: %s", pod.Status.ContainerStatuses[i].State.Terminated))
			}
		}

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

		if requestedAdmissionReview.Request.Kind.Kind == "Pod" {
			klog.Infof(fmt.Sprintf("Admission Request v1beta1 - Operation: %s", requestedAdmissionReview.Request.Operation))
			pod := &corev1.Pod{}
			if err := json.Unmarshal(requestedAdmissionReview.Request.Object.Raw, pod); err != nil {
				http.Error(w, "Failed to unmarshal pod object", http.StatusBadRequest)
				return
			}
			klog.Infof(fmt.Sprintf("Admission Request - Type: %s", pod.Kind))
			klog.Infof(fmt.Sprintf("Admission Request - POD Name: %s", pod.ObjectMeta.Name))
			klog.Infof(fmt.Sprintf("Admission Request - POD Status: %s", pod.Status.Phase))
			for i := 0; i < len(pod.Status.ContainerStatuses); i++ {
				klog.Infof(fmt.Sprintf("Admission Request - Container Name: %s", pod.Status.ContainerStatuses[i].Name))
				klog.Infof(fmt.Sprintf("Admission Request - Container State Running: %s", pod.Status.ContainerStatuses[i].State.Running))
				klog.Infof(fmt.Sprintf("Admission Request - Container State Waiting: %s", pod.Status.ContainerStatuses[i].State.Waiting))
				klog.Infof(fmt.Sprintf("Admission Request - Container State Terminated: %s", pod.Status.ContainerStatuses[i].State.Terminated))
			}
		}

	default:
		msg := fmt.Sprintf("Unsupported group version kind: %v", gvk)
		klog.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	// klog.Info(fmt.Sprintf("sending response: %v", responseObj))
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

// func serve(w http.ResponseWriter, r *http.Request) {

// 	// Initilizes the sidecar container configs
// 	// sidecarConfig := SidecarConfig{
// 	// 	Image: "openziti/ziti-tunnel:latest",
// 	// 	Name:  "zt-tunnel-proxy",
// 	// }

// 	// Read the AdmissionReview request body
// 	body, err := io.ReadAll(r.Body)
// 	if err != nil {
// 		http.Error(w, "Failed to read request body", http.StatusBadRequest)
// 		return
// 	}

// 	// verify the content type is application/json
// 	contentType := r.Header.Get("Content-Type")
// 	if contentType != "application/json" {
// 		klog.Errorf("contentType=%s, expect application/json", contentType)
// 		return
// 	}

// 	// Define AdmissionReview struct
// 	var review admissionv1.AdmissionReview

// 	// Unmarshal the request body into AdmissionReview struct
// 	if err := json.Unmarshal(body, &review); err != nil {
// 		http.Error(w, "Failed to unmarshal request body", http.StatusBadRequest)
// 		return
// 	}

// 	// Check if request is for Pod creation
// 	if review.Request.Kind.Kind != "Pod" {
// 		review.Response = &admissionv1.AdmissionResponse{
// 			UID:     review.Request.UID,
// 			Allowed: true,
// 		}
// 		response, err := json.Marshal(review)
// 		if err != nil {
// 			http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
// 			return
// 		}

// 		if _, err := w.Write(response); err != nil {
// 			http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
// 		}
// 		// klog.Infof(fmt.Sprintf("Request Operation for Returned All except POD: %s", review.Request.Operation))
// 		// klog.Infof(fmt.Sprintf("Request Operation for Returned All except POD: %s", review.Request.Operation))
// 		// klog.Infof(fmt.Sprintf("Request Operation for Returned All except POD: %s", review.Request.OldObject))
// 		return
// 	}

// 	// Extract the Pod object from the request
// 	pod := &corev1.Pod{}
// 	if err := json.Unmarshal(review.Request.Object.Raw, pod); err != nil {
// 		http.Error(w, "Failed to unmarshal pod object", http.StatusBadRequest)
// 		return
// 	}

// 	// Inject the sidecar container into the Pod spec
// 	// pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
// 	// 	Name:  sidecarConfig.Name,
// 	// 	Image: sidecarConfig.Image,
// 	// })
// 	// klog.Infof("Injected the sidecar container into the Pod spec")
// 	// Create the AdmissionReview response with the mutated Pod
// 	// patch, err := createPatch(pod.ObjectMeta, pod.Spec)
// 	// if err != nil {
// 	// 	http.Error(w, "Failed to create patch", http.StatusInternalServerError)
// 	// 	return
// 	// }
// 	// klog.Infof("Created the AdmissionReview response with the mutated Pod spec")
// 	review.Response = &admissionv1.AdmissionResponse{
// 		UID:     review.Request.UID,
// 		Allowed: true,
// 	}

// 	// Marshal the response and send it back to the API server
// 	response, err := json.Marshal(review)
// 	if err != nil {
// 		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
// 		return
// 	}

// 	if _, err := w.Write(response); err != nil {
// 		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
// 	}
// 	klog.Infof(fmt.Sprintf("Admission Request - Operation: %s", review.Request.Operation))
// 	klog.Infof(fmt.Sprintf("Admission Request - Type: %s", pod.Kind))
// 	klog.Infof(fmt.Sprintf("Admission Request - POD Name: %s", pod.ObjectMeta.Name))
// 	klog.Infof(fmt.Sprintf("Admission Request - POD Status: %s", pod.Status.Phase))
// 	for i := 0; i < len(pod.Status.ContainerStatuses); i++ {
// 		klog.Infof(fmt.Sprintf("Admission Request - Container Name: %s", pod.Status.ContainerStatuses[i].Name))
// 		klog.Infof(fmt.Sprintf("Admission Request - Container State Running: %s", pod.Status.ContainerStatuses[i].State.Running))
// 		klog.Infof(fmt.Sprintf("Admission Request - Container State Waiting: %s", pod.Status.ContainerStatuses[i].State.Waiting))
// 		klog.Infof(fmt.Sprintf("Admission Request - Container State Terminated: %s", pod.Status.ContainerStatuses[i].State.Terminated))
// 	}
// 	klog.Info("----------------------------------------------------------------")
// 	return
// }

func serveMutatePods(w http.ResponseWriter, r *http.Request) {
	serve(w, r, newDelegateToV1AdmitHandler(alwaysAllowDelayFiveSeconds))
}

func webhook(cmd *cobra.Command, args []string) {

	config := Config{
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	http.HandleFunc("/mutate-pods", serveMutatePods)
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		TLSConfig: configTLS(config),
	}
	err := server.ListenAndServeTLS("", "")
	if err != nil {
		panic(err)
	}
}
