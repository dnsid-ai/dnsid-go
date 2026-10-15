package registration

import (
	"context"
	"fmt"
	"strings"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/config"
)

func discoverAccount(ctx context.Context, client RegistryClient, expected *config.ManagedRegistrationConfig, poll time.Duration) error {
	return retry(ctx, poll, func() error {
		view, err := client.GetOrganizationOnboarding(ctx)
		if err != nil {
			return err
		}
		if view == nil || strings.TrimSpace(view.OrganizationID) == "" || view.OrganizationID != strings.TrimSpace(view.OrganizationID) {
			return fmt.Errorf("onboarding lacks a stable organization ID")
		}
		gi, err := dnsid.NormalizeFQDN(view.GovernanceDomain)
		if err != nil || view.GI == nil || view.GI.State != "verified" || !view.GI.GateAuthorized || view.EK.Status != "verified" {
			return fmt.Errorf("onboarding governance proof or entity-key delegation is not verified")
		}
		proofGI, err := dnsid.NormalizeFQDN(view.GI.Domain)
		if err != nil || proofGI != gi {
			return fmt.Errorf("onboarding governance proof differs from account domain")
		}
		if (expected.OrganizationID != "" && expected.OrganizationID != view.OrganizationID) || (expected.GovernanceID != "" && expected.GovernanceID != gi) {
			return fmt.Errorf("authenticated onboarding conflicts with configured or saved account bindings")
		}
		expected.OrganizationID, expected.GovernanceID = view.OrganizationID, gi
		return nil
	})
}
