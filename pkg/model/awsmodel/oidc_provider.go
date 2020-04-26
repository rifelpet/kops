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

const discoveryJSON = `
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

const keypairName = "service-account-signer"

func (b *OIDCProviderBuilder) Build(c *fi.ModelBuilderContext) error {
	if b.Cluster.Spec.ServiceOIDCProvider == nil || b.Cluster.Spec.ServiceOIDCProvider.IssuerHostPath == nil {
		return nil
	}
	issuerURL := fmt.Sprintf("https://%v", *b.Cluster.Spec.ServiceOIDCProvider.IssuerHostPath)

	format := string(fi.KeysetFormatV1Alpha2)
	saSigner := &fitasks.Keypair{
		Name:      fi.String(keypairName),
		Lifecycle: b.Lifecycle,
		Subject:   fmt.Sprintf("cn=%v", keypairName),
		Type:      "ca",
		Format:    format,
	}
	c.AddTask(saSigner)

	discoveryContents := fmt.Sprintf(discoveryJSON, issuerURL, issuerURL)
	discoveryFile := &fitasks.ManagedFile{
		Contents:  fi.WrapResource(fi.NewStringResource(discoveryContents)),
		Lifecycle: b.Lifecycle,
		Location:  fi.String("discovery.json"),
		Name:      fi.String("discovery.json"),
	}
	c.AddTask(discoveryFile)

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
		ClientIDs:   []*string{fi.String("sts.amazonaws.com")},
		Thumbprints: []*string{fi.String(fingerprint)},
	}
	c.AddTask(oidcProvider)

	return nil
}
