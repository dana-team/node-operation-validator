package webhook

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// NodeValidator is the struct used to validate the nodes
type NodeValidator struct {
	Decoder admission.Decoder
	Client  client.Client
	Logger  logr.Logger
}

// Operation represents the type of operation being performed
type Operation string

const (
	reasonAnnotation             = "node.dana.io/reason"
	serviceAccountUser           = "system:serviceaccount:"
	nodeUser                     = "system:node:"
	systemAdminUser              = "system:admin"
	ForbiddenUsersEnv            = "forbiddenUsers"
	Create             Operation = "create"
	Delete             Operation = "delete"
	Cordon             Operation = "cordon"
	Uncordon           Operation = "uncordon"
	cmName                       = "node-operation-validator-config"
	cmNamespace                  = "node-operation-validator-system"
)

// +kubebuilder:webhook:path=/validate-v1-node,mutating=false,failurePolicy=ignore,sideEffects=None,groups=core,resources=nodes,verbs=delete;create;update,versions=v1,name=nodeoperation.dana.io,admissionReviewVersions=v1
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

func (n *NodeValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	logger := n.Logger.WithValues("node", req.Name)

	node := corev1.Node{}
	oldNode := corev1.Node{}
	user := req.UserInfo.Username

	forbiddenUsers := strings.Split(os.Getenv(ForbiddenUsersEnv), ",")
	forbiddenUsers = append(forbiddenUsers, systemAdminUser)

	allowedReasons, err := n.getAllowedReasons(ctx, cmNamespace, logger)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, fmt.Errorf("failed to fetch allowed reasons: %w", err))
	}

	switch req.Operation {
	case admissionv1.Delete:
		if err := n.Decoder.DecodeRaw(req.OldObject, &node); err != nil {
			return admission.Errored(http.StatusBadRequest, fmt.Errorf("failed to decode node %q", req.Name))
		}
		reasonMessage, doesReasonExist := node.Annotations[reasonAnnotation]
		return userOnlyOperation(Delete, user, forbiddenUsers, reasonMessage, logger, true, doesReasonExist, allowedReasons)

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
			return userOnlyOperation(Cordon, user, forbiddenUsers, reasonMessage, logger, true, doesReasonExist, allowedReasons)

		case oldNode.Spec.Unschedulable && !node.Spec.Unschedulable:
			return userOnlyOperation(Uncordon, user, forbiddenUsers, reasonMessage, logger, false, doesReasonExist, allowedReasons)

		default:
			return admission.Allowed("Node was updated")
		}
	}
}

// userOnlyOperation checks whether a given user is allowed to perform a specific operation on a node.
// It returns an admission response indicating whether the operation is allowed or denied.
func userOnlyOperation(operation Operation, user string, forbiddenUsers []string, reasonMessage string, log logr.Logger, isReasonRequired bool, doesReasonExist bool, allowedReasons []string) admission.Response {
	switch {
	case isForbiddenUser(user, forbiddenUsers):
		log.Info(fmt.Sprintf("%s node denied", operation), "DenialReason", "forbidden user", "User", user)
		return admission.Denied(fmt.Sprintf("%q user is not allowed to %s a node. Please log in with a LDAP privileged user. You must also add %q annotation", user, operation, reasonAnnotation))

	case isServiceAccount(user):
		log.Info(fmt.Sprintf("%s node approved", operation), "User", user, "ApprovalReason", "Service account is allowed to do any operation")
		return admission.Allowed(fmt.Sprintf("Service account %q is allowed to do everything", user))

	case isNode(user):
		log.Info(fmt.Sprintf("%s node approved", operation), "User", user, "ApprovalReason", "Node is allowed to do any operation")
		return admission.Allowed(fmt.Sprintf("Node %q is allowed to do everything", user))

	default:
		if isReasonRequired {
			if doesReasonExist {
				if reasonIsAllowed(allowedReasons, reasonMessage) {
					log.Info(fmt.Sprintf("%s node approved", operation), "User", user, "Reason", reasonMessage)
					return admission.Allowed(fmt.Sprintf("%s operation has been approved", operation))
				}
				log.Info(fmt.Sprintf("%s node denied", operation), "DenialReason", "invalid reason", "User", user, "Reason", reasonMessage)
				return admission.Denied(fmt.Sprintf("Invalid reason %q. Allowed reasons: %v", reasonMessage, allowedReasons))
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

// isServiceAccount returns true if the given user is a service account.
func isServiceAccount(user string) bool {
	return strings.HasPrefix(user, serviceAccountUser)
}

func isNode(user string) bool {
	return strings.HasPrefix(user, nodeUser)
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

// getAllowedReasons fetches the allowed reasons from the ConfigMap.
func (n *NodeValidator) getAllowedReasons(ctx context.Context, namespace string, logger logr.Logger) ([]string, error) {
	configMapReasons := corev1.ConfigMap{}
	if err := n.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: cmName}, &configMapReasons); err != nil {
		logger.Error(err, "Failed to fetch ConfigMap", "Namespace", namespace, "Name", cmName)
		return nil, fmt.Errorf("failed to fetch ConfigMap %s/%s: %w", namespace, cmName, err)
	}

	allowedReasons, ok := configMapReasons.Data["allowedReasons"]
	if !ok {
		return nil, fmt.Errorf("ConfigMap %s/%s does not contain 'allowedReasons' key", namespace, cmName)
	}
	reasons := strings.Split(allowedReasons, ",")
	return reasons, nil
}

// reasonIsAllowed checks if the reason message exists in the allowed reasons list.
func reasonIsAllowed(allowedReasons []string, reason string) bool {
	for _, allowedReason := range allowedReasons {
		if strings.EqualFold(allowedReason, reason) {
			return true
		}
	}
	return false
}
