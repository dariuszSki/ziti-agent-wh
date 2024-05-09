package main

import (
	"fmt"
	"strings"
	"ziti-agent-wh/zitiEdge"

	"github.com/google/uuid"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

const (
	podsSidecarPatch string = `[
		{"op":"add", "path":"/spec/containers/-","value":{"image":"%v","name":"%v","command":["/bin/bash"] ,"args":["-c", "while true; do ping localhost; sleep 60;done"],"resources":{}}}
	]`
	zitiCtrlAddress string = `https://e64a9603-3a63-47b4-9690-104fc5491db0.production.netfoundry.io:443`
)

func zitiTunnel(ar admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	reviewResponse := admissionv1.AdmissionResponse{}
	pod := corev1.Pod{}
	zitiCfg := zitiEdge.Config{ApiEndpoint: zitiCtrlAddress, Username: "ZTUSER050CE2D7A352708ADDDDB3095BD7E1D4757608C1", Password: "ZTPASSAB3C1AF0CEE671C3E26578A3C5FA85F7EA26D0DA"}

	switch ar.Request.Operation {
	case "CREATE":
		klog.Infof(fmt.Sprintf("%s", ar.Request.Operation))
		if _, _, err := deserializer.Decode(ar.Request.Object.Raw, nil, &pod); err != nil {
			klog.Error(err)
			return toV1AdmissionResponse(err)
		}

		id := uuid.New()
		sidecarIdentityName := fmt.Sprintf("%s-%s-%s", pod.Labels["app"], sidecarName, id)

		klog.Infof(fmt.Sprintf("Creating Ziti Identity"))
		zitiClient, err := zitiEdge.Client(&zitiCfg)
		if err != nil {
			klog.Error(err)
		}

		klog.Infof(fmt.Sprintf("Sidecar Name is %s", sidecarIdentityName))

		identityDetails, err := zitiEdge.GetIdentityByName(sidecarIdentityName, zitiClient)
		if err != nil {
			klog.Error(err)
		}

		var zId string = ""

		for _, identityItem := range identityDetails.GetPayload().Data {
			zId = *identityItem.ID
		}

		klog.Infof(fmt.Sprintf("ziti id length %d", len(zId)))

		if len(zId) == 0 {
			identityDetails, err := zitiEdge.CreateIdentity(sidecarIdentityName, "Device", zitiClient)
			if err != nil {
				klog.Error(err)
			}
			klog.Infof(fmt.Sprintf("Created Ziti Identity zId: %s", identityDetails.GetPayload().Data.ID))
		}

		reviewResponse.Patch = []byte(fmt.Sprintf(podsSidecarPatch, sidecarImage, sidecarIdentityName))
		pt := admissionv1.PatchTypeJSONPatch
		reviewResponse.PatchType = &pt

	case "UPDATE":
		klog.Infof(fmt.Sprintf("%s", ar.Request.Operation))
		newPod := false
		oldPod := false
		if _, _, err := deserializer.Decode(ar.Request.Object.Raw, nil, &pod); err != nil {
			klog.Error(err)
			return toV1AdmissionResponse(err)
		}

		sidecarIdentityName := hasContainer(pod.Spec.Containers, fmt.Sprintf("%s-%s-%s", pod.Labels["app"], sidecarName))
		if len(sidecarIdentityName) == 0 {
			newPod = true
		}

		if _, _, err := deserializer.Decode(ar.Request.OldObject.Raw, nil, &pod); err != nil {
			klog.Error(err)
			return toV1AdmissionResponse(err)
		}

		sidecarIdentityName = hasContainer(pod.Spec.Containers, fmt.Sprintf("%s-%s-%s", pod.Labels["app"], sidecarName))
		if len(sidecarIdentityName) == 0 {
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
		klog.Infof(fmt.Sprintf("%s", ar.Request.Operation))
		if _, _, err := deserializer.Decode(ar.Request.OldObject.Raw, nil, &pod); err != nil {
			klog.Error(err)
			return toV1AdmissionResponse(err)
		}

		sidecarIdentityName := hasContainer(pod.Spec.Containers, fmt.Sprintf("%s-%s", pod.Labels["app"], sidecarName))

		if len(sidecarIdentityName) > 0 {

			klog.Infof(fmt.Sprintf("Deleting Ziti Identity"))

			zitiClient, err := zitiEdge.Client(&zitiCfg)
			if err != nil {
				klog.Error(err)
			}

			klog.Infof(fmt.Sprintf("Sidecar Name is %s", sidecarIdentityName))

			identityDetails, err := zitiEdge.GetIdentityByName(sidecarIdentityName, zitiClient)
			if err != nil {
				klog.Error(err)
			}

			var zId string = ""

			for _, identityItem := range identityDetails.GetPayload().Data {
				zId = *identityItem.ID
			}

			klog.Infof(fmt.Sprintf("ziti id length %d", len(zId)))

			// kclient := kclient()
			// podStatus, err := kclient.CoreV1().Events(pod.Namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: fmt.Sprintf("app=%s", appLabel["app"])})
			// if err != nil {
			// 	klog.Error(err)
			// }

			// klog.Infof(fmt.Sprintf("Pod Status %s", podStatus))

			if len(zId) > 0 {
				err = zitiEdge.DeleteIdentity(zId, zitiClient)
				if err != nil {
					klog.Error(err)
				}
			}

		}

	}

	// klog.Infof(fmt.Sprintf("This webhook path allows ziti-tunnel requests"))

	reviewResponse.Allowed = true
	reviewResponse.Result = &metav1.Status{Message: "This webhook path allows ziti-tunnel requests"}
	// klog.Infof(fmt.Sprintf("Response is %s", &reviewResponse))
	return &reviewResponse
}

func hasContainer(containers []corev1.Container, containerName string) string {
	for _, container := range containers {
		if strings.HasPrefix(container.Name, containerName) {
			return container.Name
		}
	}
	return ""
}
