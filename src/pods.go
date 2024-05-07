package main

import (
	"fmt"
	"time"

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

func updateSidecar(ar admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	klog.Info("always-allow-with-delay sleeping for 5 seconds")
	time.Sleep(5 * time.Second)
	klog.Info("this webhook path allows update requests")
	reviewResponse := admissionv1.AdmissionResponse{}
	reviewResponse.Allowed = true
	reviewResponse.Result = &metav1.Status{Message: "this webhook path allows update requests"}
	return &reviewResponse
}

func deleteSidecar(ar admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	if !isPodResource(ar) {
		return nil
	}

	raw := ar.Request.OldObject.Raw
	pod := corev1.Pod{}
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(raw, nil, &pod); err != nil {
		klog.Error(err)
		return toV1AdmissionResponse(err)
	}

	shouldPatchPod := func(pod *corev1.Pod) bool {
		return !hasContainer(pod.Spec.Containers, sidecarName)
	}
	return applyPodPatch(shouldPatchPod, &pod, fmt.Sprintf(podsSidecarPatch, sidecarImage, sidecarName))
}

func createSidecar(ar admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	if !isPodResource(ar) {
		return nil
	}

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

	raw := ar.Request.Object.Raw
	pod := corev1.Pod{}
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(raw, nil, &pod); err != nil {
		klog.Error(err)
		return toV1AdmissionResponse(err)
	}

	shouldPatchPod := func(pod *corev1.Pod) bool {
		return !hasContainer(pod.Spec.Containers, sidecarName)
	}
	return applyPodPatch(shouldPatchPod, &pod, fmt.Sprintf(podsSidecarPatch, sidecarImage, sidecarName))
}

func isPodResource(ar admissionv1.AdmissionReview) bool {
	podResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	if ar.Request.Resource != podResource {
		klog.Errorf("expect resource to be %s", podResource)
		return false
	}
	return true
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

func applyPodPatch(shouldPatchPod func(*corev1.Pod) bool, pod *corev1.Pod, patch string) *admissionv1.AdmissionResponse {
	klog.Info("mutating pods")

	reviewResponse := admissionv1.AdmissionResponse{}
	reviewResponse.Allowed = true
	if shouldPatchPod(pod) {
		reviewResponse.Patch = []byte(patch)
		pt := admissionv1.PatchTypeJSONPatch
		reviewResponse.PatchType = &pt
	} else {
		reviewResponse.Result = &metav1.Status{Message: "this webhook path allows delete requests"}
		klog.Infof(fmt.Sprintf("Container %s exists, entire pod is being deleted.", sidecarName))
	}
	return &reviewResponse
}
