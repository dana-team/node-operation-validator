package webhook

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// NodeValidator is the struct used to validate the nodes
type NodeValidator struct {
	Decoder *admission.Decoder
	Client  client.Client
}

// Operation represents the type of operation being performed
type Operation string

const (
	reasonAnnotation             = "node.dana.io/reason"
	serviceAccountUser           = "system:serviceaccount:"
	systemAdminUser              = "system:admin"
	ForbiddenUsersEnv            = "forbiddenUsers"
	Create             Operation = "create"
	Delete             Operation = "delete"
	Cordon             Operation = "cordon"
	Uncordon           Operation = "uncordon"
)

// +kubebuilder:webhook:path=/validate-v1-node,mutating=false,failurePolicy=ignore,sideEffects=None,groups=core,resources=nodes,verbs=delete;create;update,versions=v1,name=nodeoperation.dana.io,admissionReviewVersions=v1

func (n *NodeValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	logger := log.FromContext(ctx).WithName("Node Webhook").WithValues("node", req.Name)

	node := corev1.Node{}
	oldNode := corev1.Node{}
	user := req.UserInfo.Username

	forbiddenUsers := strings.Split(os.Getenv(ForbiddenUsersEnv), ",")
	forbiddenUsers = append(forbiddenUsers, systemAdminUser)

	switch req.Operation {
	case admissionv1.Delete:
		if err := n.Decoder.DecodeRaw(req.OldObject, &node); err != nil {
			return admission.Errored(http.StatusBadRequest, fmt.Errorf("failed to decode node %q", req.Name))
		}
		reasonMessage, doesReasonExist := node.Annotations[reasonAnnotation]
		return userOnlyOperation(Delete, user, forbiddenUsers, reasonMessage, logger, true, doesReasonExist)

	case admissionv1.Create:
		if err := n.Decoder.DecodeRaw(req.Object, &node); err != nil {
			return admission.Errored(http.StatusBadRequest, fmt.Errorf("failed to decode node %q", req.Name))
		}
		_, doesReasonExist := node.Annotations[reasonAnnotation]
		return validateNoReason(doesReasonExist, logger, Create, user)

	// The default case handles the update requests.
	default:
		if err := n.Decoder.DecodeRaw(req.OldObject, &node); err != nil {
			return admission.Errored(http.StatusBadRequest, fmt.Errorf("failed to decode node %q", req.Name))
		}
		if err := n.Decoder.DecodeRaw(req.Object, &node); err != nil {
			return admission.Errored(http.StatusBadRequest, fmt.Errorf("failed to decode node %q", req.Name))
		}
		reasonMessage, doesReasonExist := node.Annotations[reasonAnnotation]

		switch {
		case !oldNode.Spec.Unschedulable && node.Spec.Unschedulable:
			return userOnlyOperation(Cordon, user, forbiddenUsers, reasonMessage, logger, true, doesReasonExist)

		case oldNode.Spec.Unschedulable && !node.Spec.Unschedulable:
			return userOnlyOperation(Uncordon, user, forbiddenUsers, reasonMessage, logger, false, doesReasonExist)

		default:
			return admission.Allowed("Node was updated")
		}
	}
}

// userOnlyOperation checks whether a given user is allowed to perform a specific operation on a node.
// It returns an admission response indicating whether the operation is allowed or denied.
func userOnlyOperation(operation Operation, user string, forbiddenUsers []string, reasonMessage string, log logr.Logger, isReasonRequired bool, doesReasonExist bool) admission.Response {
	switch {
	case isForbiddenUser(user, forbiddenUsers):
		log.Info(fmt.Sprintf("%s node denied", operation), "DenialReason", "forbidden user", "User", user)
		if doesReasonExist {
			return admission.Denied(fmt.Sprintf("%q user is not allowed to %s a node. Please log in with a LDAP privileged user", user, operation))
		} else {
			return admission.Denied(fmt.Sprintf("%q user is not allowed to %s a node. Please log in with a LDAP privileged user. You must also add %q annotation", user, operation, reasonAnnotation))
		}

	case isServiceAccount(user):
		log.Info(fmt.Sprintf("%s node approved", operation), "User", user, "ApprovalReason", "Service account is allowed to do any operation")
		return admission.Allowed(fmt.Sprintf("Service account %q is allowed to do everything", user))

	default:
		if isReasonRequired {
			if doesReasonExist {
				log.Info(fmt.Sprintf("%s node approved", operation), "User", user, "Reason", reasonMessage)
				return admission.Allowed(fmt.Sprintf("%s operation has been approved", operation))
			} else {
				log.Info(fmt.Sprintf("%s node denied", operation), "DenialReason", "reason annotation doesn't exist", "User", user)
				return admission.Denied(fmt.Sprintf("You must add %q annotation", reasonAnnotation))
			}
		} else {
			return validateNoReason(doesReasonExist, log, operation, user)
		}
	}
}

// validateNoReason checks if reason annotation exists when doing an operation.
// If the reason exists, it denies the request. If it doesn't - the operation is approved and logged.
func validateNoReason(doesReasonExist bool, log logr.Logger, operation Operation, user string) admission.Response {
	if doesReasonExist {
		log.Info(fmt.Sprintf("%s node denied", operation), "DenialReason", "reason annotation exists", "User", user)
		return admission.Denied(fmt.Sprintf("Don't forget to remove the %q annotation from the node", reasonAnnotation))
	} else {
		log.Info(fmt.Sprintf("%s node approved", operation), "User", user)
		return admission.Allowed("Operation approved")
	}
}

// isServiceAccount returns true if the given user is a service account
func isServiceAccount(user string) bool {
	return strings.HasPrefix(user, serviceAccountUser)
}

// isForbiddenUser checks if the given user is in the list of forbidden users.
func isForbiddenUser(userToCheck string, forbiddenUsers []string) bool {
	for _, user := range forbiddenUsers {
		if user == userToCheck {
			return true
		}
	}
	return false
}
