/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package awsmodel

import (
	"fmt"

	"k8s.io/kops/pkg/model"
	"k8s.io/kops/pkg/sshcredentials"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/cloudup/awstasks"
	"k8s.io/kops/upup/pkg/fi/fitasks"
)

// OIDCProviderBuilder configures IAM OIDC Provider
type OIDCProviderBuilder struct {
	*model.KopsModelContext

	KeyStore  fi.CAStore
	Lifecycle *fi.Lifecycle
}

var _ fi.ModelBuilder = &OIDCProviderBuilder{}

const (
	keypairName   = "service-account-signer"
	stsAudience   = "sts.amazonaws.com"
	discoveryJSON = `
{
		"issuer": "%v/",
		"jwks_uri": "%v/keys.json",
		"authorization_endpoint": "urn:kubernetes:programmatic_authorization",
		"response_types_supported": [
						"id_token"
		],
		"subject_types_supported": [
						"public"
		],
		"id_token_signing_alg_values_supported": [
						"RS256"
		],
		"claims_supported": [
						"sub",
						"iss"
		]
}`
)

func (b *OIDCProviderBuilder) Build(c *fi.ModelBuilderContext) error {
	if b.Cluster.Spec.ServiceOIDCProvider == nil || b.Cluster.Spec.ServiceOIDCProvider.Issuer == nil {
		return nil
	}
	issuerURL := *b.Cluster.Spec.ServiceOIDCProvider.Issuer

	format := string(fi.KeysetFormatV1Alpha2)
	saSigner := &fitasks.Keypair{
		Name:      fi.String(keypairName),
		Lifecycle: b.Lifecycle,
		Subject:   fmt.Sprintf("cn=%v", keypairName),
		Type:      "ca",
		Format:    format,
	}
	c.AddTask(saSigner)

	// Webhook CA and certs
	{
		podIdentityWebhookCA := &fitasks.Keypair{
			Name:      fi.String("pod-identity-webhook-ca"),
			Lifecycle: b.Lifecycle,
			Subject:   fmt.Sprintf("cn=%v", keypairName),
			Type:      "ca",
			Format:    format,
		}
		c.AddTask(podIdentityWebhookCA)

		podIdentityWebhook := &fitasks.Keypair{
			Name:      fi.String("pod-identity-webhook"),
			Lifecycle: b.Lifecycle,
			Signer:    podIdentityWebhookCA,
			Subject:   "cn=pod-identity-webhook",
			Type:      "server",
			Format:    format,
		}
		c.AddTask(podIdentityWebhook)
	}

	discoveryContents := fmt.Sprintf(discoveryJSON, issuerURL, issuerURL)
	discoveryFile := &fitasks.ManagedFile{
		Contents:  fi.WrapResource(fi.NewStringResource(discoveryContents)),
		Lifecycle: b.Lifecycle,
		Location:  fi.String("discovery.json"),
		Name:      fi.String("discovery.json"),
	}
	c.AddTask(discoveryFile)

	// TODO create keys.json from https://github.com/aws/amazon-eks-pod-identity-webhook/blob/master/hack/self-hosted/main.go
	keysContents := ""
	keysFile := &fitasks.ManagedFile{
		Contents:  fi.WrapResource(fi.NewStringResource(keysContents)),
		Lifecycle: b.Lifecycle,
		Location:  fi.String("keys.json"),
		Name:      fi.String("keys.json"),
	}
	c.AddTask(keysFile)

	cert, _, _, err := b.KeyStore.FindKeypair(keypairName)
	if err != nil {
		return err
	}
	if cert == nil {
		return fmt.Errorf("keypair has not been created yet: %v", keypairName)
	}
	pubKey, err := cert.AsString()
	if err != nil {
		return err
	}
	fingerprint, err := sshcredentials.Fingerprint(pubKey)
	if err != nil {
		return err
	}
	oidcProvider := &awstasks.IAMOIDCProvider{
		Name:        fi.String(b.ClusterName()),
		Lifecycle:   b.Lifecycle,
		URL:         fi.String(issuerURL),
		ClientIDs:   []*string{fi.String(stsAudience)},
		Thumbprints: []*string{fi.String(fingerprint)},
	}
	c.AddTask(oidcProvider)

	return nil
}
