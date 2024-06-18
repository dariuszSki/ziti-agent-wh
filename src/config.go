package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"strconv"
	"strings"

	"k8s.io/klog/v2"
)

// Define sidecar config options
type SidecarConfig struct {
	Image string `json:"image"`
	Name  string `json:"name"`
}

func configTLS(cert, key []byte) *tls.Config {
	sCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		klog.Fatalf("Failed to load the 509x certs %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{sCert},
		// TODO: uses mutual tls after we agree on what cert the apiserver should use.
		// ClientAuth:   tls.RequireAndVerifyClientCert,
	}
}

func lookupEnvVars() {
	// Environmental Variables to override the commandline inputs
	value, ok = os.LookupEnv("TLS-CERT")
	if ok {
		cert = []byte(value)
	} else {
		if len(cert) == 0 {
			klog.Infof(fmt.Sprintf("Webhook Server tls cert is not set"))
		}
	}
	value, ok = os.LookupEnv("TLS-PRIVATE-KEY")
	if ok {
		key = []byte(value)
	} else {
		if len(key) == 0 {
			klog.Infof(fmt.Sprintf("Webhook Server tls private key is not set"))
		}
	}
	value, ok = os.LookupEnv("PORT")
	if ok {
		port, _ = strconv.Atoi(value)
	} else {
		if port <= 0 {
			klog.Infof(fmt.Sprintf("Webhook Server Port is not set"))
		}
	}
	value, ok = os.LookupEnv("SIDECAR_IMAGE")
	if ok {
		sidecarImage = value
	} else {
		if len(sidecarImage) == 0 {
			klog.Infof(fmt.Sprintf("Sidecar Image is not set"))
		}
	}
	value, ok = os.LookupEnv("SIDECAR_IMAGE_VERSION")
	if ok {
		sidecarImageVersion = value
	} else {
		if len(sidecarImageVersion) == 0 {
			klog.Infof(fmt.Sprintf("Sidecar Image Version is not set"))
		}
	}
	value, ok = os.LookupEnv("SIDECAR_PREFIX")
	if ok {
		sidecarPrefix = value
	} else {
		if len(sidecarPrefix) == 0 {
			klog.Infof(fmt.Sprintf("Sidecar Prefix is not set"))
		}
	}
	value, ok = os.LookupEnv("ZITI_CTRL_ADDRESS")
	if ok {
		zitiCtrlAddress = value
	} else {
		if len(zitiCtrlAddress) == 0 {
			klog.Infof(fmt.Sprintf("Ziti Controller Address is not set"))
		}
	}
	value, ok = os.LookupEnv("ZITI_CTRL_USERNAME")
	if ok {
		zitiCtrlUsername = value
	} else {
		if len(zitiCtrlUsername) == 0 {
			klog.Infof(fmt.Sprintf("Ziti Controller Username is not set"))
		}
	}
	value, ok = os.LookupEnv("ZITI_CTRL_PASSWORD")
	if ok {
		zitiCtrlPassword = value
	} else {
		if len(zitiCtrlPassword) == 0 {
			klog.Infof(fmt.Sprintf("Ziti Controller Password is not set"))
		}
	}
	value, ok = os.LookupEnv("POD_SECURITY_CONTEXT_OVERRIDE")
	if ok {
		var err error
		podSecurityOverride, err = strconv.ParseBool(value)
		if err != nil {
			klog.Info(err)
		}
	}
	value, ok = os.LookupEnv("CLUSTER_DNS_SVC_IP")
	if ok {
		clusterDnsServiceIP = value
	} else {
		if len(clusterDnsServiceIP) == 0 {
			klog.Infof(fmt.Sprintf("Custom DNS Server IP is not set"))
			klog.Infof(fmt.Sprintf("DNS Service ClusterIP will be looked up"))
		}
	}
	value, ok = os.LookupEnv("SEARCH_DOMAIN_LIST")
	if ok {
		searchDomainList = []string(strings.Split(value, ","))
	} else {
		if len(searchDomainList) == 0 {
			klog.Infof(fmt.Sprintf("A list of DNS search domains for host-name lookup is empty"))
		}
	}
	value, ok = os.LookupEnv("ZITI_ROLE_KEY")
	if ok {
		zitiRoleKey = value
	} else {
		if len(zitiRoleKey) == 0 {
			klog.Infof(fmt.Sprintf("A ziti role key is not present in the pod annotations"))
		}
	}
}
