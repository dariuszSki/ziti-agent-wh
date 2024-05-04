package main

import (
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

// alwaysAllowDelayFiveSeconds sleeps for five seconds and allows all requests made to this function.
func alwaysAllowDelayFiveSeconds(ar admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	klog.Info("always-allow-with-delay sleeping for 5 seconds")
	time.Sleep(5 * time.Second)
	klog.Info("calling always-allow")
	reviewResponse := admissionv1.AdmissionResponse{}
	reviewResponse.Allowed = true
	reviewResponse.Result = &metav1.Status{Message: "this webhook allows all requests"}
	return &reviewResponse
}
