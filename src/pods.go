package main

import (
	"fmt"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

const (
	podsSidecarPatch string = `[
		{"op":"add", "path":"/spec/containers/-","value":{"image":"%v","name":"%v","command":["/bin/bash"] ,"args":["-c", "while true; do ping localhost; sleep 60;done"],"resources":{}}}
	]`
)

func mutatePodsSidecar(ar admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	if sidecarImage == "" {
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  "Failure",
				Message: "No image specified by the sidecar-image parameter",
				Code:    500,
			},
		}
	}
	shouldPatchPod := func(pod *corev1.Pod) bool {
		return !hasContainer(pod.Spec.Containers, sidecarName)
	}
	return applyPodPatch(ar, shouldPatchPod, fmt.Sprintf(podsSidecarPatch, sidecarImage, sidecarName))
}

func hasContainer(containers []corev1.Container, containerName string) bool {
	for _, container := range containers {
		klog.Infof(fmt.Sprintf("Admission Request - Container Specs: %s", &container))
		klog.Infof(fmt.Sprintf("Admission Request - Container Name: %s", container.Name))
		klog.Infof(fmt.Sprintf("Admission Request - Container Cmd: %s", container.Command))
		klog.Infof(fmt.Sprintf("Admission Request - Container Args: %s", container.Args))
		if container.Name == containerName {
			return true
		}
	}
	return false
}

func applyPodPatch(ar admissionv1.AdmissionReview, shouldPatchPod func(*corev1.Pod) bool, patch string) *admissionv1.AdmissionResponse {
	klog.Info("mutating pods")
	podResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	if ar.Request.Resource != podResource {
		klog.Errorf("expect resource to be %s", podResource)
		return nil
	}

	raw := ar.Request.Object.Raw // Object.Raw
	pod := corev1.Pod{}
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(raw, nil, &pod); err != nil {
		klog.Error(err)
		return toV1AdmissionResponse(err)
	}
	// klog.Info(fmt.Sprintf("Request Object: %s", raw))
	// klog.Infof(fmt.Sprintf("Admission Request - Type: %s", pod.Kind))
	// klog.Infof(fmt.Sprintf("Admission Request - Object Meta: %s", &pod.ObjectMeta))
	// klog.Infof(fmt.Sprintf("Admission Request - Object Meta: %s", &pod.ObjectMeta))
	// klog.Infof(fmt.Sprintf("Admission Request - POD Status: %s", pod.Status.Phase))
	// for i := 0; i < len(pod.Status.ContainerStatuses); i++ {
	// 	klog.Infof(fmt.Sprintf("Admission Request - Container Name: %s", pod.Status.ContainerStatuses[i].Name))
	// 	klog.Infof(fmt.Sprintf("Admission Request - Container State Running: %s", pod.Status.ContainerStatuses[i].State.Running))
	// 	klog.Infof(fmt.Sprintf("Admission Request - Container State Waiting: %s", pod.Status.ContainerStatuses[i].State.Waiting))
	// 	klog.Infof(fmt.Sprintf("Admission Request - Container State Terminated: %s", pod.Status.ContainerStatuses[i].State.Terminated))
	// }

	reviewResponse := admissionv1.AdmissionResponse{}
	reviewResponse.Allowed = true
	if shouldPatchPod(&pod) {
		reviewResponse.Patch = []byte(patch)
		pt := admissionv1.PatchTypeJSONPatch
		reviewResponse.PatchType = &pt
	}
	return &reviewResponse
}
