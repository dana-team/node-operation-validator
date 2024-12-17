package webhook

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	testclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	regularUserExample = "user"
)

func newScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = scheme.AddToScheme(s)
	return s
}

func newFakeClient() client.Client {
	scm := newScheme()
	return testclient.NewClientBuilder().WithScheme(scm).Build()
}

func TestNodeWebhook(t *testing.T) {
	tests := []struct {
		name      string
		operation admissionv1.Operation
		user      string
		reason    string
		allowed   bool
	}{
		{name: "CreateWithReason", operation: admissionv1.Create, user: regularUserExample, reason: "Testing", allowed: false},
		{name: "CreateWithoutReason", operation: admissionv1.Create, user: regularUserExample, reason: "", allowed: true},
		{name: "DeleteAsKubeadminWithReason", operation: admissionv1.Delete, user: systemAdminUser, reason: "Testing", allowed: false},
		{name: "DeleteAsUserWithoutReason", operation: admissionv1.Delete, user: regularUserExample, reason: "", allowed: false},
		{name: "DeleteAsUserWithValidReason", operation: admissionv1.Delete, user: regularUserExample, reason: "testing", allowed: true},
		{name: "DeleteAsUserWithoutValidReason", operation: admissionv1.Delete, user: regularUserExample, reason: "for fun", allowed: false},
		{name: "CordonAsKubeadminWithReason", operation: "cordon", user: systemAdminUser, reason: "Testing", allowed: false},
		{name: "CordonAsUserWithoutReason", operation: "cordon", user: regularUserExample, reason: "", allowed: false},
		{name: "CordonAsUserWithReason", operation: "cordon", user: regularUserExample, reason: "Testing", allowed: true},
		{name: "CordonAsServiceAccountWithoutReason", operation: "cordon", user: serviceAccountUser + "openshift-machine-config-operator:machine-config-daemon", reason: "", allowed: true},
		{name: "UncordonAsKubeadminWithoutReason", operation: "uncordon", user: systemAdminUser, reason: "", allowed: false},
		{name: "UncordonAsUserWithReason", operation: "uncordon", user: regularUserExample, reason: "Testing", allowed: false},
		{name: "UncordonAsUserWithoutReason", operation: "uncordon", user: regularUserExample, reason: "", allowed: true},
		{name: "UncordonAsServiceAccountWithReason", operation: "uncordon", user: serviceAccountUser + "openshift-machine-config-operator:machine-config-daemon", reason: "testing", allowed: true},
	}
	fakeClient := newFakeClient()

	mockConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: cmNamespace,
		},
		Data: map[string]string{
			"allowedReasons": strings.Join([]string{
				"Testing",
				"Unauthorized access",
				"Invalid configuration",
				"Dependency error",
			}, ","),
		},
	}
	err := fakeClient.Create(context.Background(), mockConfigMap)
	if err != nil {
		t.Fatalf("Failed to create mocked ConfigMap: %v", err)
	}

	ctx := context.Background()
	g := NewWithT(t)
	decoder := admission.NewDecoder(scheme.Scheme)
	nv := NodeValidator{Decoder: decoder, Client: fakeClient}

	err = os.Setenv(ForbiddenUsersEnv, systemAdminUser)
	if err != nil {
		print(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			annotations := make(map[string]string)
			if test.reason != "" {
				annotations[reasonAnnotation] = test.reason
			}
			node := corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: test.name,
					Annotations: annotations},
			}
			cordonedNode := corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: test.name,
					Annotations: annotations},
				Spec: corev1.NodeSpec{Unschedulable: true},
			}
			nodeObj, err := json.Marshal(node)
			g.Expect(err).ShouldNot(HaveOccurred())

			cordonedNodeObj, err := json.Marshal(cordonedNode)
			g.Expect(err).ShouldNot(HaveOccurred())

			// In case of create operation - tries to create a node and ensures the response is as expected.
			if test.operation == admissionv1.Create {
				createReq := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Name: test.name,
					Operation: test.operation,
					UserInfo:  v1.UserInfo{Username: test.user},
					Kind:      metav1.GroupVersionKind{Kind: "Node", Group: "core", Version: "v1"},
					Object:    runtime.RawExtension{Raw: nodeObj}}}
				response := nv.Handle(ctx, createReq)
				g.Expect(response.Allowed).Should(Equal(test.allowed))
			}

			// In case of delete operation - create an empty node, add relevant annotations to it and update,
			// tries to delete the node with the given user and reason, and ensures the response is as expected.
			if test.operation == admissionv1.Delete {
				emptyNode := corev1.Node{
					ObjectMeta: metav1.ObjectMeta{Name: test.name},
				}
				err := fakeClient.Create(ctx, &emptyNode)
				if err != nil {
					print(err.Error())
				}
				emptyNode.Annotations = annotations
				err = fakeClient.Update(ctx, &emptyNode)
				if err != nil {
					print(err.Error())
				}
				deleteReq := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Name: test.name,
					Operation: admissionv1.Delete,
					UserInfo:  v1.UserInfo{Username: test.user},
					Kind:      metav1.GroupVersionKind{Kind: "Node", Group: "core", Version: "v1"},
					OldObject: runtime.RawExtension{Raw: nodeObj}}}
				response := nv.Handle(ctx, deleteReq)
				g.Expect(response.Allowed).Should(Equal(test.allowed))
			}

			// In case of cordon operation - create an empty node, and tries to cordon the node
			// with the given user and reason and ensures the response is es expected.
			if test.operation == "cordon" {
				err := fakeClient.Create(ctx, &node)
				if err != nil {
					print(err.Error())
				}
				updateReq := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Name: test.name,
					Operation: admissionv1.Update,
					UserInfo:  v1.UserInfo{Username: test.user},
					Kind:      metav1.GroupVersionKind{Kind: "Node", Group: "core", Version: "v1"},
					OldObject: runtime.RawExtension{Raw: nodeObj},
					Object:    runtime.RawExtension{Raw: cordonedNodeObj}}}
				response := nv.Handle(ctx, updateReq)
				g.Expect(response.Allowed).Should(Equal(test.allowed))

				// In case of uncordon operation - create a cordoned node, and tries to uncordon the node
				// with the given user and reason and ensures the response is es expected.
				if test.operation == "uncordon" {
					err := fakeClient.Create(ctx, &cordonedNode)
					if err != nil {
						print(err.Error())
					}
					UpdateReq := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Name: test.name,
						Operation: admissionv1.Update,
						UserInfo:  v1.UserInfo{Username: test.user},
						Kind:      metav1.GroupVersionKind{Kind: "Node", Group: "core", Version: "v1"},
						OldObject: runtime.RawExtension{Raw: cordonedNodeObj},
						Object:    runtime.RawExtension{Raw: nodeObj}}}
					response := nv.Handle(ctx, UpdateReq)
					g.Expect(response.Allowed).Should(Equal(test.allowed))
				}
			}
		})
	}
}
