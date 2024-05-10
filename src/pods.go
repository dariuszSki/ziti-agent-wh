package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"ziti-agent-wh/zitiEdge"

	"github.com/google/uuid"
	"github.com/openziti/sdk-golang/ziti"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

const (
	volumeMountName string = "sidecar-ziti-identity"
)

type JsonPatchEntry struct {
	OP    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value,omitempty"`
}

func zitiTunnel(ar admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	reviewResponse := admissionv1.AdmissionResponse{}
	pod := corev1.Pod{}
	zitiCfg := zitiEdge.Config{ApiEndpoint: zitiCtrlAddress, Username: zitiCtrlUsername, Password: zitiCtrlPassword}

	switch ar.Request.Operation {
	case "CREATE":
		klog.Infof(fmt.Sprintf("%s", ar.Request.Operation))
		if _, _, err := deserializer.Decode(ar.Request.Object.Raw, nil, &pod); err != nil {
			klog.Error(err)
			return toV1AdmissionResponse(err)
		}

		identityCfg, sidecarIdentityName := createAndEnrollIdentity(pod.Labels["app"], zitiCfg)
		secretData, err := json.Marshal(identityCfg)
		if err != nil {
			klog.Error(err)
		}

		// kubernetes client
		kclient := kclient()

		//Create secret in the same namespace
		secretStatus, err := kclient.CoreV1().Secrets(pod.Namespace).Create(context.TODO(), &corev1.Secret{Data: map[string][]byte{sidecarIdentityName: secretData}, Type: "Opaque", ObjectMeta: metav1.ObjectMeta{Name: sidecarIdentityName}}, metav1.CreateOptions{})
		if err != nil {
			klog.Error(err)
		}
		klog.Infof(fmt.Sprintf("Secret %s was created at %s", secretStatus.Name, secretStatus.CreationTimestamp))

		// add sidecar volume to pod
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: volumeMountName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: sidecarIdentityName,
					Items:      []corev1.KeyToPath{{Key: sidecarIdentityName, Path: fmt.Sprintf("%v.json", sidecarIdentityName)}},
				},
			},
		})

		volumesBytes, err := json.Marshal(&pod.Spec.Volumes)
		if err != nil {
			klog.Error(err)
		}

		// add sidecar container to pod
		pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
			Name:            sidecarIdentityName,
			Image:           sidecarImage,
			Args:            []string{"tproxy", "-i", fmt.Sprintf("%v.json", sidecarIdentityName)},
			VolumeMounts:    []corev1.VolumeMount{{Name: volumeMountName, MountPath: "/netfoundry", ReadOnly: true}},
			SecurityContext: &corev1.SecurityContext{Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}}},
		})

		containersBytes, err := json.Marshal(&pod.Spec.Containers)
		if err != nil {
			klog.Error(err)
		}

		// build json patch
		patch := []JsonPatchEntry{

			JsonPatchEntry{
				OP:    "add",
				Path:  "/spec/containers",
				Value: containersBytes,
			},
			JsonPatchEntry{
				OP:    "add",
				Path:  "/spec/volumes",
				Value: volumesBytes,
			},
		}

		patchBytes, err := json.Marshal(&patch)
		if err != nil {
			klog.Error(err)
		}

		reviewResponse.Patch = patchBytes
		klog.Infof(fmt.Sprintf("Patch bytes: %s", reviewResponse.Patch))
		pt := admissionv1.PatchTypeJSONPatch
		reviewResponse.PatchType = &pt

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

			// kubernetes client
			kclient := kclient()
			secretData, err := kclient.CoreV1().Secrets(pod.Namespace).Get(context.TODO(), sidecarIdentityName, metav1.GetOptions{})
			if err != nil {
				klog.Error(err)
			}
			if len(secretData.Name) > 0 {
				err = kclient.CoreV1().Secrets(pod.Namespace).Delete(context.TODO(), sidecarIdentityName, metav1.DeleteOptions{})
				if err != nil {
					klog.Error(err)
				} else {
					klog.Infof(fmt.Sprintf("Secret %s was deleted at %s", sidecarIdentityName, secretData.DeletionTimestamp))
				}

			}

			if len(zId) > 0 {
				err = zitiEdge.DeleteIdentity(zId, zitiClient)
				if err != nil {
					klog.Error(err)
				}
			}

		}

	}

	reviewResponse.Allowed = true
	reviewResponse.Result = &metav1.Status{Message: "Completed deletion operation"}
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

func createSidecarIdentityName(appName string) string {
	id := uuid.New()
	return fmt.Sprintf("%s-%s-%s", appName, sidecarName, id)
}

func createAndEnrollIdentity(name string, config zitiEdge.Config) (*ziti.Config, string) {
	identityName := createSidecarIdentityName(name)
	klog.Infof(fmt.Sprintf("Sidecar Name is %s", identityName))

	zitiClient, err := zitiEdge.Client(&config)
	if err != nil {
		klog.Error(err)
	}

	identityDetails, _ := zitiEdge.CreateIdentity(identityName, "Device", zitiClient)
	klog.Infof(fmt.Sprintf("Created Ziti Identity zId: %s", identityDetails.GetPayload().Data.ID))

	identityCfg, _ := zitiEdge.EnrollIdentity(identityDetails.GetPayload().Data.ID, zitiClient)
	klog.Infof(fmt.Sprintf("Enrolled Ziti Identity cfg API: %s", identityCfg.ZtAPI))

	// TODO create secret for ziti-tunnel in pod namespace

	return identityCfg, identityName

}
