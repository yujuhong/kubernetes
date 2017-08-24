/*
Copyright 2017 The Kubernetes Authors.

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

package gce

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	computealpha "google.golang.org/api/compute/v0.alpha"

	"k8s.io/api/core/v1"
)

func TestEnsureStaticIP(t *testing.T) {
	fcas := NewFakeCloudAddressService()
	ipName := "some-static-ip"
	serviceName := ""
	region := "us-central1"

	// First ensure call
	ip, existed, err := ensureStaticIP(fcas, ipName, serviceName, region, "", NetworkTierDefault)
	if err != nil || existed || ip == "" {
		t.Fatalf(`ensureStaticIP(%v, %v, %v, %v, "") = %v, %v, %v; want valid ip, false, nil`, fcas, ipName, serviceName, region, ip, existed, err)
	}

	// Second ensure call
	var ipPrime string
	ipPrime, existed, err = ensureStaticIP(fcas, ipName, serviceName, region, ip, NetworkTierDefault)
	if err != nil || !existed || ip != ipPrime {
		t.Fatalf(`ensureStaticIP(%v, %v, %v, %v, %v) = %v, %v, %v; want %v, true, nil`, fcas, ipName, serviceName, region, ip, ipPrime, existed, err, ip)
	}
}

func TestEnsureStaticIPWithTier(t *testing.T) {
	s := NewFakeCloudAddressService()
	serviceName := ""
	region := "us-east1"

	for desc, tc := range map[string]struct {
		name     string
		netTier  NetworkTier
		expected string
	}{
		"Premium (default)": {
			name:     "foo-1",
			netTier:  NetworkTierPremium,
			expected: "PREMIUM",
		},
		"Standard": {
			name:     "foo-2",
			netTier:  NetworkTierStandard,
			expected: "STANDARD",
		},
	} {
		t.Run(desc, func(t *testing.T) {
			ip, existed, err := ensureStaticIP(s, tc.name, serviceName, region, "", tc.netTier)
			assert.NoError(t, err)
			assert.False(t, existed)
			assert.NotEqual(t, "", ip)
			// Get the Address from the fake address service and verify that the tier
			// is set correctly.
			alphaAddr, err := s.GetAlphaRegionAddress(tc.name, region)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, alphaAddr.NetworkTier)
		})
	}
}

func TestVerifyRequestedIP(t *testing.T) {
	region := "test-region"
	lbRef := "test-lb"
	s := NewFakeCloudAddressService()

	for desc, tc := range map[string]struct {
		requestedIP     string
		fwdRuleIP       string
		addrList        []*computealpha.Address
		expectErr       bool
		expectUserOwned bool
	}{
		"requested IP exists": {
			requestedIP:     "1.1.1.1",
			addrList:        []*computealpha.Address{{Name: "foo", Address: "1.1.1.1"}},
			expectErr:       false,
			expectUserOwned: true,
		},
		"requested IP is not static, but is in use by the fwd rule": {
			requestedIP: "1.1.1.1",
			fwdRuleIP:   "1.1.1.1",
			expectErr:   false,
		},
		"requested IP is not static and is not used by the fwd rule": {
			requestedIP: "1.1.1.1",
			fwdRuleIP:   "2.2.2.2",
			expectErr:   true,
		},
		"no requested IP": {
			expectErr: false,
		},
	} {
		t.Run(desc, func(t *testing.T) {
			s.SetRegionalAddresses(region, tc.addrList)
			isUserOwnedIP, err := verifyUserRequestedIP(s, region, tc.requestedIP, tc.fwdRuleIP, lbRef)
			assert.Equal(t, tc.expectErr, err != nil, fmt.Sprintf("err: %v", err))
			assert.Equal(t, tc.expectUserOwned, isUserOwnedIP, desc)
		})
	}
}

func TestCreateForwardingRule(t *testing.T) {
	s := NewFakeCloudForwardingRuleService()
	// Common variables among the tests.
	ports := []v1.ServicePort{{Name: "foo", Protocol: v1.ProtocolTCP, Port: int32(123)}}
	region := "test-region"
	target := "test-target-pool"
	svcName := "foo-svc"

	for desc, tc := range map[string]struct {
		netTier      NetworkTier
		expectedRule *computealpha.ForwardingRule
	}{
		"Premium tier": {
			netTier: NetworkTierPremium,
			expectedRule: &computealpha.ForwardingRule{
				Name:        "lb-1",
				Description: `{"kubernetes.io/service-name":"foo-svc"}`,
				IPAddress:   "1.1.1.1",
				IPProtocol:  "TCP",
				PortRange:   "123-123",
				Target:      target,
				NetworkTier: "PREMIUM",
			},
		},
		"Standard tier": {
			netTier: NetworkTierStandard,
			expectedRule: &computealpha.ForwardingRule{
				Name:        "lb-2",
				Description: `{"kubernetes.io/service-name":"foo-svc"}`,
				IPAddress:   "2.2.2.2",
				IPProtocol:  "TCP",
				PortRange:   "123-123",
				Target:      target,
				NetworkTier: "STANDARD",
			},
		},
	} {
		t.Run(desc, func(t *testing.T) {
			lbName := tc.expectedRule.Name
			ipAddr := tc.expectedRule.IPAddress

			err := createForwardingRule(s, lbName, svcName, region, ipAddr, target, ports, tc.netTier)
			assert.NoError(t, err)

			alphaRule, err := s.GetAlphaRegionForwardingRule(lbName, region)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedRule, alphaRule)
		})
	}
}
