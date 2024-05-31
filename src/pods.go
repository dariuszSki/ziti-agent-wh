package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
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
	oldPod := corev1.Pod{}
	zitiCfg := zitiEdge.Config{ApiEndpoint: zitiCtrlAddress, Username: zitiCtrlUsername, Password: zitiCtrlPassword}

	klog.Infof(fmt.Sprintf("Admission Request UID: %s", ar.Request.UID))
	switch ar.Request.Operation {

	case "CREATE":
		klog.Infof(fmt.Sprintf("%s", ar.Request.Operation))
		klog.Infof(fmt.Sprintf("Object: %s", ar.Request.Object.Raw))
		klog.Infof(fmt.Sprintf("OldObject: %s", ar.Request.OldObject.Raw))
		if _, _, err := deserializer.Decode(ar.Request.Object.Raw, nil, &pod); err != nil {
			klog.Error(err)
			return toV1AdmissionResponse(err)
		}

		// klog.Infof(fmt.Sprintf("Owners are %s", pod.OwnerReferences[0].UID))
		// klog.Infof(fmt.Sprintf("Pod UID is %s", pod.UID))
		klog.Infof(fmt.Sprintf("Pod Labels are %s", pod.Labels))
		klog.Infof(fmt.Sprintf("Pod Annotations are %s", pod.Annotations))

		roles, ok := getIdentityAttributes(pod.Annotations)
		if !ok {
			roles = []string{pod.Labels["app"]}
		}

		identityCfg, sidecarIdentityName := createAndEnrollIdentity(pod.Labels["app"], roles, zitiCfg)
		secretData, err := json.Marshal(identityCfg)
		if err != nil {
			klog.Error(err)
		}

		// kubernetes client
		kclient := kclient()

		//Create secret in the same namespace
		_, err = kclient.CoreV1().Secrets(pod.Namespace).Create(context.TODO(), &corev1.Secret{Data: map[string][]byte{sidecarIdentityName: secretData}, Type: "Opaque", ObjectMeta: metav1.ObjectMeta{Name: sidecarIdentityName}}, metav1.CreateOptions{})
		if err != nil {
			klog.Error(err)
		}

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

		// update pod dns config and policy
		pod.Spec.DNSConfig = &corev1.PodDNSConfig{
			Nameservers: []string{"127.0.0.1", clusterDnsServiceIP},
			Searches:    searchDomainList,
		}
		dnsConfigBytes, err := json.Marshal(&pod.Spec.DNSConfig)
		if err != nil {
			klog.Error(err)
		}

		pod.Spec.DNSPolicy = "None"
		dnsPolicyBytes, err := json.Marshal(&pod.Spec.DNSPolicy)
		if err != nil {
			klog.Error(err)
		}

		var podSecurityContextBytes []byte
		var patch []JsonPatchEntry
		var rootUser int64 = 0
		var isNotTrue bool = false
		var sidecarSecurityContext *corev1.SecurityContext

		sidecarSecurityContext = &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}},
		}

		if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsUser != nil {
			// run sidecar as root
			sidecarSecurityContext = &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}},
				RunAsUser:    &rootUser,
			}
		}

		pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
			Name:            sidecarIdentityName,
			Image:           fmt.Sprintf("%s:%s", sidecarImage, sidecarImageVersion),
			Args:            []string{"tproxy", "-i", fmt.Sprintf("%v.json", sidecarIdentityName)},
			VolumeMounts:    []corev1.VolumeMount{{Name: volumeMountName, MountPath: "/netfoundry", ReadOnly: true}},
			SecurityContext: sidecarSecurityContext,
		})

		containersBytes, err := json.Marshal(&pod.Spec.Containers)
		if err != nil {
			klog.Error(err)
		}

		patch = []JsonPatchEntry{

			{
				OP:    "add",
				Path:  "/spec/containers",
				Value: containersBytes,
			},
			{
				OP:    "add",
				Path:  "/spec/volumes",
				Value: volumesBytes,
			},
			{
				OP:    "replace",
				Path:  "/spec/dnsPolicy",
				Value: dnsPolicyBytes,
			},
			{
				OP:    "add",
				Path:  "/spec/dnsConfig",
				Value: dnsConfigBytes,
			},
		}

		// update Pod Security Context RunAsNonRoot to false
		if podSecurityOverride {
			pod.Spec.SecurityContext.RunAsNonRoot = &isNotTrue
			podSecurityContextBytes, err = json.Marshal(&pod.Spec.SecurityContext)
			if err != nil {
				klog.Error(err)
			}
			patch = append(patch, []JsonPatchEntry{
				{
					OP:    "replace",
					Path:  "/spec/securityContext",
					Value: podSecurityContextBytes,
				},
			}...)
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

		zName, ok := hasContainer(pod.Spec.Containers, fmt.Sprintf("%s-%s", pod.Labels["app"], sidecarPrefix))
		if ok {
			// kubernetes client
			kclient := kclient()
			secretData, err := kclient.CoreV1().Secrets(pod.Namespace).Get(context.TODO(), zName, metav1.GetOptions{})
			if err != nil {
				klog.Error(err)
			}
			if len(secretData.Name) > 0 {
				err = kclient.CoreV1().Secrets(pod.Namespace).Delete(context.TODO(), zName, metav1.DeleteOptions{})
				if err != nil {
					klog.Error(err)
				} else {
					klog.Infof(fmt.Sprintf("Secret %s was deleted at %s", zName, secretData.DeletionTimestamp))
				}

			}

			zId, ok := findIdentity(zName, zitiCfg)
			if ok {
				zitiClient, err := zitiEdge.Client(&zitiCfg)
				if err != nil {
					klog.Error(err)
				}

				err = zitiEdge.DeleteIdentity(zId, zitiClient)
				if err != nil {
					klog.Error(err)
				}
			}
		}

	case "UPDATE":
		klog.Infof(fmt.Sprintf("%s", ar.Request.Operation))
		klog.Infof(fmt.Sprintf("Object: %s", ar.Request.Object.Raw))
		klog.Infof(fmt.Sprintf("OldObject: %s", ar.Request.OldObject.Raw))
		if _, _, err := deserializer.Decode(ar.Request.Object.Raw, nil, &pod); err != nil {
			klog.Error(err)
			return toV1AdmissionResponse(err)
		}
		if _, _, err := deserializer.Decode(ar.Request.OldObject.Raw, nil, &oldPod); err != nil {
			klog.Error(err)
			return toV1AdmissionResponse(err)
		}

		zName, ok := hasContainer(pod.Spec.Containers, fmt.Sprintf("%s-%s", pod.Labels["app"], sidecarPrefix))
		if ok {
			var roles []string
			klog.Infof(fmt.Sprintf("Pod Annotations are %s", pod.Annotations))
			newRoles, newOk := getIdentityAttributes(pod.Annotations)
			klog.Infof(fmt.Sprintf("OldPod Annotations are %s", oldPod.Annotations))
			oldRoles, oldOk := getIdentityAttributes(oldPod.Annotations)

			if !newOk && oldOk {
				// Ziti Annotation is removed
				roles = []string{pod.Labels["app"]}
			} else if newOk && !reflect.DeepEqual(newRoles, oldRoles) {
				//Ziti Annotation is created or updated
				roles = newRoles
			} else {
				roles = []string{}
			}

			klog.Infof(fmt.Sprintf("Roles are %s", roles))
			klog.Infof(fmt.Sprintf("Roles length is %d", len(roles)))
			// Update only if Ziti Annotation is changed
			if len(roles) > 0 {
				zitiClient, err := zitiEdge.Client(&zitiCfg)
				if err != nil {
					klog.Error(err)
				}
				zId, ok := findIdentity(zName, zitiCfg)
				if ok {
					identityDetails, err := zitiEdge.PatchIdentity(zId, roles, zitiClient)
					if err != nil {
						klog.Error(err)
					}
					klog.Infof(fmt.Sprintf("Updated Identity Details are %v", identityDetails))
				}
			}
		}

	}
	reviewResponse.Allowed = true
	reviewResponse.Result = &metav1.Status{Message: fmt.Sprintf("Completed %s operation", ar.Request.Operation)}
	return &reviewResponse
}

func hasContainer(containers []corev1.Container, containerName string) (string, bool) {
	for _, container := range containers {
		if strings.HasPrefix(container.Name, containerName) {
			return container.Name, true
		}
	}
	return "", false
}

func createSidecarIdentityName(appName string) string {
	id, _ := uuid.NewV7()
	return fmt.Sprintf("%s-%s%s", trimString(appName), sidecarPrefix, id)
}

func createAndEnrollIdentity(name string, roles []string, config zitiEdge.Config) (*ziti.Config, string) {
	identityName := createSidecarIdentityName(name)
	// klog.Infof(fmt.Sprintf("Sidecar Name is %s", identityName))

	zitiClient, err := zitiEdge.Client(&config)
	if err != nil {
		klog.Error(err)
	}

	identityDetails, _ := zitiEdge.CreateIdentity(identityName, roles, "Device", zitiClient)
	//klog.Infof(fmt.Sprintf("Created Ziti Identity zId: %s", identityDetails.GetPayload().Data.ID))

	identityCfg, err := zitiEdge.EnrollIdentity(identityDetails.GetPayload().Data.ID, zitiClient)
	if err != nil {
		klog.Error(err)
	}
	// klog.Infof(fmt.Sprintf("Enrolled Ziti Identity cfg API: %s", identityCfg.ZtAPI))

	return identityCfg, identityName
}

func findIdentity(name string, config zitiEdge.Config) (string, bool) {

	var zId string = ""
	// klog.Infof(fmt.Sprintf("Deleting Ziti Identity"))

	zitiClient, err := zitiEdge.Client(&config)
	if err != nil {
		klog.Error(err)
	}

	identityDetails, err := zitiEdge.GetIdentityByName(name, zitiClient)
	if err != nil {
		klog.Error(err)
	}

	for _, identityItem := range identityDetails.GetPayload().Data {
		zId = *identityItem.ID
	}

	if len(zId) > 0 {
		klog.Infof(fmt.Sprintf("Identity Id is %s", zId))
		return zId, true
	}

	return zId, false
}

func getIdentityAttributes(roles map[string]string) ([]string, bool) {
	// if a ziti role key is not present, use app name as a role attribute
	value, ok = roles[zitiRoleKey]
	if ok {
		if len(value) > 0 {
			return strings.Split(value, ","), true
		}
	}
	return []string{}, false
}

func trimString(input string) string {
	if len(input) > 24 {
		return input[:24]
	}
	return input
}
