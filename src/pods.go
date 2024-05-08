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

func zitiTunnel(ar admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	reviewResponse := admissionv1.AdmissionResponse{}
	pod := corev1.Pod{}

	switch ar.Request.Operation {
	case "CREATE":
		klog.Infof(fmt.Sprintf("Create"))
		if _, _, err := deserializer.Decode(ar.Request.Object.Raw, nil, &pod); err != nil {
			klog.Error(err)
			return toV1AdmissionResponse(err)
		}
		if !hasContainer(pod.Spec.Containers, sidecarName) {
			//TODO create ziti indentity and attribute
			klog.Infof(fmt.Sprintf("Creating Ziti Identity"))
			reviewResponse.Patch = []byte(fmt.Sprintf(podsSidecarPatch, sidecarImage, sidecarName))
			pt := admissionv1.PatchTypeJSONPatch
			reviewResponse.PatchType = &pt
		}
	case "UPDATE":
		klog.Infof(fmt.Sprintf("Update"))
		newPod := false
		oldPod := false
		if _, _, err := deserializer.Decode(ar.Request.Object.Raw, nil, &pod); err != nil {
			klog.Error(err)
			return toV1AdmissionResponse(err)
		}

		if !hasContainer(pod.Spec.Containers, sidecarName) {
			newPod = true
		}

		if _, _, err := deserializer.Decode(ar.Request.OldObject.Raw, nil, &pod); err != nil {
			klog.Error(err)
			return toV1AdmissionResponse(err)
		}

		if !hasContainer(pod.Spec.Containers, sidecarName) {
			oldPod = true
		}

		if newPod && oldPod {
			//TODO create ziti indentity and attribute
			klog.Infof(fmt.Sprintf("Creating Ziti Identity"))
			reviewResponse.Patch = []byte(fmt.Sprintf(podsSidecarPatch, sidecarImage, sidecarName))
			pt := admissionv1.PatchTypeJSONPatch
			reviewResponse.PatchType = &pt
		}

	case "DELETE":
		klog.Infof(fmt.Sprintf("Delete"))
		if _, _, err := deserializer.Decode(ar.Request.OldObject.Raw, nil, &pod); err != nil {
			klog.Error(err)
			return toV1AdmissionResponse(err)
		}
		if hasContainer(pod.Spec.Containers, sidecarName) {
			//TODO delete ziti indentity
			klog.Infof(fmt.Sprintf("Deleting Ziti Identity"))
		}

	}

	// klog.Infof(fmt.Sprintf("This webhook path allows ziti-tunnel requests"))

	reviewResponse.Allowed = true
	reviewResponse.Result = &metav1.Status{Message: "This webhook path allows ziti-tunnel requests"}
	// klog.Infof(fmt.Sprintf("Response is %s", &reviewResponse))
	return &reviewResponse
}

func hasContainer(containers []corev1.Container, containerName string) bool {
	for _, container := range containers {
		if container.Name == containerName {
			return true
		}
	}
	return false
}
