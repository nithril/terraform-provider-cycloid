package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/cycloidio/cycloid-cli/client/models"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/stretchr/testify/assert"
)

// generateTestSSHKey generates an RSA SSH key for testing
func generateTestSSHKey() (string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return string(privateKeyPEM), nil
}

func TestAccCredentialResource_AWS(t *testing.T) {
	t.Parallel()

	credName := RandomCanonical("test-aws-cred")
	const credDesc = "Test AWS credential for acceptance testing"

	orgCanonical := testAccGetOrganizationCanonical()
	ctx := context.Background()
	depManager := NewTestDependencyManager(t)
	defer depManager.Cleanup(ctx, t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: depManager.GetProviderFactories(),
		PreCheck:                 func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Create AWS credential with organization_canonical parameter
			{
				Config: testAccCredentialConfig_aws(orgCanonical, credName, credDesc),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cycloid_credential.test", "organization_canonical", orgCanonical),
					resource.TestCheckResourceAttr("cycloid_credential.test", "name", credName),
					resource.TestCheckResourceAttr("cycloid_credential.test", "description", credDesc),
					resource.TestCheckResourceAttr("cycloid_credential.test", "type", "aws"),
					resource.TestCheckResourceAttr("cycloid_credential.test", "path", credName),
				),
			},
			// Update credential
			{
				Config: testAccCredentialConfig_aws_updated(orgCanonical, credName+"-updated", credDesc+" updated"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cycloid_credential.test", "organization_canonical", orgCanonical),
					resource.TestCheckResourceAttr("cycloid_credential.test", "name", credName+"-updated"),
					resource.TestCheckResourceAttr("cycloid_credential.test", "description", credDesc+" updated"),
					resource.TestCheckResourceAttr("cycloid_credential.test", "type", "aws"),
					resource.TestCheckResourceAttr("cycloid_credential.test", "path", credName+"-updated"),
				),
			},
			// Destroy testing
			{
				Config:  " ", // Empty config to trigger destroy
				Destroy: true,
			},
		},
	})
}

// TestAccCredentialResource_CanonicalChangeForcesReplace reproduces the
// "Provider produced inconsistent result after apply" bug on `.canonical`.
// Before the RequiresReplaceIfConfigured plan modifier, changing an
// explicitly-configured canonical was planned as an in-place update that kept
// the old (state) canonical and wrote it back, mismatching the planned value.
// The change must now be planned and applied as a replacement instead.
func TestAccCredentialResource_CanonicalChangeForcesReplace(t *testing.T) {
	t.Parallel()

	orgCanonical := testAccGetOrganizationCanonical()
	ctx := context.Background()
	depManager := NewTestDependencyManager(t)
	defer depManager.Cleanup(ctx, t)

	name := RandomCanonical("test-cred-canon")
	canonical1 := RandomCanonical("cred-canon-one")
	canonical2 := RandomCanonical("cred-canon-two")
	const desc = "credential canonical replacement test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: depManager.GetProviderFactories(),
		PreCheck:                 func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Create with an explicit canonical.
			{
				Config: testAccCredentialConfig_awsWithCanonical(orgCanonical, name, canonical1, desc),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cycloid_credential.test", "canonical", canonical1),
				),
			},
			// Change the canonical: it must force a replacement, not an in-place
			// update, and must not error with an inconsistent result.
			{
				Config: testAccCredentialConfig_awsWithCanonical(orgCanonical, name, canonical2, desc),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("cycloid_credential.test", plancheck.ResourceActionReplace),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cycloid_credential.test", "canonical", canonical2),
				),
			},
			// Destroy testing
			{
				Config:  " ", // Empty config to trigger destroy
				Destroy: true,
			},
		},
	})
}

func TestAccCredentialResource_SSH(t *testing.T) {
	t.Parallel()

	credName := RandomCanonical("test-ssh-cred")
	const credDesc = "Test SSH credential for acceptance testing"

	orgCanonical := testAccGetOrganizationCanonical()
	ctx := context.Background()
	depManager := NewTestDependencyManager(t)
	defer depManager.Cleanup(ctx, t)

	// Generate SSH key for testing
	sshKey, err := generateTestSSHKey()
	if err != nil {
		t.Fatalf("Failed to generate SSH key: %v", err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: depManager.GetProviderFactories(),
		PreCheck:                 func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Create SSH credential with organization_canonical parameter
			{
				Config: testAccCredentialConfig_ssh(orgCanonical, credName, credDesc, sshKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cycloid_credential.test", "organization_canonical", orgCanonical),
					resource.TestCheckResourceAttr("cycloid_credential.test", "name", credName),
					resource.TestCheckResourceAttr("cycloid_credential.test", "description", credDesc),
					resource.TestCheckResourceAttr("cycloid_credential.test", "type", "ssh"),
				),
			},
			// Destroy testing
			{
				Config:  " ", // Empty config to trigger destroy
				Destroy: true,
			},
		},
	})
}

func TestAccCredentialResource_BasicAuth(t *testing.T) {
	t.Parallel()

	credName := RandomCanonical("test-basic-auth-cred")
	const credDesc = "Test basic auth credential for acceptance testing"

	orgCanonical := testAccGetOrganizationCanonical()
	ctx := context.Background()
	depManager := NewTestDependencyManager(t)
	defer depManager.Cleanup(ctx, t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: depManager.GetProviderFactories(),
		PreCheck:                 func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Create basic auth credential with organization_canonical parameter
			{
				Config: testAccCredentialConfig_basic_auth(orgCanonical, credName, credDesc),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cycloid_credential.test", "organization_canonical", orgCanonical),
					resource.TestCheckResourceAttr("cycloid_credential.test", "name", credName),
					resource.TestCheckResourceAttr("cycloid_credential.test", "description", credDesc),
					resource.TestCheckResourceAttr("cycloid_credential.test", "type", "basic_auth"),
				),
			},
			// Destroy testing
			{
				Config:  " ", // Empty config to trigger destroy
				Destroy: true,
			},
		},
	})
}

func TestAccCredentialResource_Azure(t *testing.T) {
	t.Parallel()

	credName := RandomCanonical("test-azure-cred")
	const credDesc = "Test Azure credential for acceptance testing"

	orgCanonical := testAccGetOrganizationCanonical()
	ctx := context.Background()
	depManager := NewTestDependencyManager(t)
	defer depManager.Cleanup(ctx, t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: depManager.GetProviderFactories(),
		PreCheck:                 func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Create Azure credential with organization_canonical parameter
			{
				Config: testAccCredentialConfig_azure(orgCanonical, credName, credDesc),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cycloid_credential.test", "organization_canonical", orgCanonical),
					resource.TestCheckResourceAttr("cycloid_credential.test", "name", credName),
					resource.TestCheckResourceAttr("cycloid_credential.test", "description", credDesc),
					resource.TestCheckResourceAttr("cycloid_credential.test", "type", "azure"),
				),
			},
			// Destroy testing
			{
				Config:  " ", // Empty config to trigger destroy
				Destroy: true,
			},
		},
	})
}

func TestAccCredentialResource_AzureStorage(t *testing.T) {
	t.Parallel()

	credName := RandomCanonical("test-azure-storage-cred")
	const credDesc = "Test Azure Storage credential for acceptance testing"

	orgCanonical := testAccGetOrganizationCanonical()
	ctx := context.Background()
	depManager := NewTestDependencyManager(t)
	defer depManager.Cleanup(ctx, t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: depManager.GetProviderFactories(),
		PreCheck:                 func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Create Azure Storage credential with organization_canonical parameter
			{
				Config: testAccCredentialConfig_azure_storage(orgCanonical, credName, credDesc),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cycloid_credential.test", "organization_canonical", orgCanonical),
					resource.TestCheckResourceAttr("cycloid_credential.test", "name", credName),
					resource.TestCheckResourceAttr("cycloid_credential.test", "description", credDesc),
					resource.TestCheckResourceAttr("cycloid_credential.test", "type", "azure_storage"),
				),
			},
			// Destroy testing
			{
				Config:  " ", // Empty config to trigger destroy
				Destroy: true,
			},
		},
	})
}

func TestAccCredentialResource_GCP(t *testing.T) {
	t.Parallel()

	credName := RandomCanonical("test-gcp-cred")
	const credDesc = "Test GCP credential for acceptance testing"

	orgCanonical := testAccGetOrganizationCanonical()
	ctx := context.Background()
	depManager := NewTestDependencyManager(t)
	defer depManager.Cleanup(ctx, t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: depManager.GetProviderFactories(),
		PreCheck:                 func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Create GCP credential with organization_canonical parameter
			{
				Config: testAccCredentialConfig_gcp(orgCanonical, credName, credDesc),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cycloid_credential.test", "organization_canonical", orgCanonical),
					resource.TestCheckResourceAttr("cycloid_credential.test", "name", credName),
					resource.TestCheckResourceAttr("cycloid_credential.test", "description", credDesc),
					resource.TestCheckResourceAttr("cycloid_credential.test", "type", "gcp"),
				),
			},
			// Destroy testing
			{
				Config:  " ", // Empty config to trigger destroy
				Destroy: true,
			},
		},
	})
}

func TestAccCredentialResource_Elasticsearch(t *testing.T) {
	t.Parallel()

	credName := RandomCanonical("test-elasticsearch-cred")
	const credDesc = "Test Elasticsearch credential for acceptance testing"

	orgCanonical := testAccGetOrganizationCanonical()
	ctx := context.Background()
	depManager := NewTestDependencyManager(t)
	defer depManager.Cleanup(ctx, t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: depManager.GetProviderFactories(),
		PreCheck:                 func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Create Elasticsearch credential with organization_canonical parameter
			{
				Config: testAccCredentialConfig_elasticsearch(orgCanonical, credName, credDesc),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cycloid_credential.test", "organization_canonical", orgCanonical),
					resource.TestCheckResourceAttr("cycloid_credential.test", "name", credName),
					resource.TestCheckResourceAttr("cycloid_credential.test", "description", credDesc),
					resource.TestCheckResourceAttr("cycloid_credential.test", "type", "elasticsearch"),
				),
			},
			// Destroy testing
			{
				Config:  " ", // Empty config to trigger destroy
				Destroy: true,
			},
		},
	})
}

func TestAccCredentialResource_Swift(t *testing.T) {
	t.Parallel()

	credName := RandomCanonical("test-swift-cred")
	const credDesc = "Test Swift credential for acceptance testing"

	orgCanonical := testAccGetOrganizationCanonical()
	ctx := context.Background()
	depManager := NewTestDependencyManager(t)
	defer depManager.Cleanup(ctx, t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: depManager.GetProviderFactories(),
		PreCheck:                 func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Create Swift credential with organization_canonical parameter
			{
				Config: testAccCredentialConfig_swift(orgCanonical, credName, credDesc),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cycloid_credential.test", "organization_canonical", orgCanonical),
					resource.TestCheckResourceAttr("cycloid_credential.test", "name", credName),
					resource.TestCheckResourceAttr("cycloid_credential.test", "description", credDesc),
					resource.TestCheckResourceAttr("cycloid_credential.test", "type", "swift"),
				),
			},
			// Destroy testing
			{
				Config:  " ", // Empty config to trigger destroy
				Destroy: true,
			},
		},
	})
}

func TestAccCredentialResource_Custom(t *testing.T) {
	t.Parallel()

	credName := RandomCanonical("test-custom-cred")
	const credDesc = "Test custom credential for acceptance testing"

	orgCanonical := testAccGetOrganizationCanonical()
	ctx := context.Background()
	depManager := NewTestDependencyManager(t)
	defer depManager.Cleanup(ctx, t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: depManager.GetProviderFactories(),
		PreCheck:                 func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Create custom credential with organization_canonical parameter
			{
				Config: testAccCredentialConfig_custom(orgCanonical, credName, credDesc),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cycloid_credential.test", "organization_canonical", orgCanonical),
					resource.TestCheckResourceAttr("cycloid_credential.test", "name", credName),
					resource.TestCheckResourceAttr("cycloid_credential.test", "description", credDesc),
					resource.TestCheckResourceAttr("cycloid_credential.test", "type", "custom"),
				),
			},
			// Destroy testing
			{
				Config:  " ", // Empty config to trigger destroy
				Destroy: true,
			},
		},
	})
}

// Test configuration functions
func testAccCredentialConfig_aws(org, name, desc string) string {
	return fmt.Sprintf(`
resource "cycloid_credential" "test" {
  organization_canonical = "%s"
  name                  = "%s"
  description           = "%s"
  type                  = "aws"
  path                  = "%s"
  
  body = {
    access_key = "test-access-key"
    secret_key = "test-secret-key"
  }
}
`, org, name, desc, name)
}

func testAccCredentialConfig_aws_updated(org, name, desc string) string {
	return fmt.Sprintf(`
resource "cycloid_credential" "test" {
  organization_canonical = "%s"
  name                  = "%s"
  description           = "%s"
  type                  = "aws"
  path                  = "%s"
  
  body = {
    access_key = "test-access-key-updated"
    secret_key = "test-secret-key-updated"
  }
}
`, org, name, desc, name)
}

func testAccCredentialConfig_awsWithCanonical(org, name, canonical, desc string) string {
	return fmt.Sprintf(`
resource "cycloid_credential" "test" {
  organization_canonical = "%s"
  name                   = "%s"
  canonical              = "%s"
  description            = "%s"
  type                   = "aws"
  path                   = "%s"

  body = {
    access_key = "test-access-key"
    secret_key = "test-secret-key"
  }
}
`, org, name, canonical, desc, canonical)
}

func testAccCredentialConfig_ssh(org, name, desc, sshKey string) string {
	return fmt.Sprintf(`
resource "cycloid_credential" "test" {
  organization_canonical = "%s"
  name                  = "%s"
  description           = "%s"
  type                  = "ssh"
  path                  = "%s"
  
  body = {
    ssh_key = chomp(<<EOF
%s
EOF
)
  }
}
`, org, name, desc, name, sshKey)
}

func testAccCredentialConfig_basic_auth(org, name, desc string) string {
	return fmt.Sprintf(`
resource "cycloid_credential" "test" {
  organization_canonical = "%s"
  name                  = "%s"
  description           = "%s"
  type                  = "basic_auth"
  path                  = "%s"
  
  body = {
    username = "testuser"
    password = "testpass"
  }
}
`, org, name, desc, name)
}

func testAccCredentialConfig_azure(org, name, desc string) string {
	return fmt.Sprintf(`
resource "cycloid_credential" "test" {
  organization_canonical = "%s"
  name                  = "%s"
  description           = "%s"
  type                  = "azure"
  path                  = "%s"
  
  body = {
    client_id       = "test-client-id"
    client_secret   = "test-client-secret"
    tenant_id       = "test-tenant-id"
    subscription_id = "test-subscription-id"
  }
}
`, org, name, desc, name)
}

func testAccCredentialConfig_azure_storage(org, name, desc string) string {
	return fmt.Sprintf(`
resource "cycloid_credential" "test" {
  organization_canonical = "%s"
  name                  = "%s"
  description           = "%s"
  type                  = "azure_storage"
  path                  = "%s"
  
  body = {
    access_key   = "test-access-key"
    account_name = "test-account-name"
  }
}
`, org, name, desc, name)
}

func testAccCredentialConfig_gcp(org, name, desc string) string {
	return fmt.Sprintf(`
resource "cycloid_credential" "test" {
  organization_canonical = "%s"
  name                  = "%s"
  description           = "%s"
  type                  = "gcp"
  path                  = "%s"
  
  body = {
    json_key = "test-json-key-content"
  }
}
`, org, name, desc, name)
}

func testAccCredentialConfig_elasticsearch(org, name, desc string) string {
	return fmt.Sprintf(`
resource "cycloid_credential" "test" {
  organization_canonical = "%s"
  name                  = "%s"
  description           = "%s"
  type                  = "elasticsearch"
  path                  = "%s"
  
  body = {
    username = "testuser"
    password = "testpass"
  }
}
`, org, name, desc, name)
}

func testAccCredentialConfig_swift(org, name, desc string) string {
	return fmt.Sprintf(`
resource "cycloid_credential" "test" {
  organization_canonical = "%s"
  name                  = "%s"
  description           = "%s"
  type                  = "swift"
  path                  = "%s"
  
  body = {
    username = "testuser"
    password = "testpass"
    auth_url  = "https://auth.example.com"
    tenant_id = "test-tenant-id"
  }
}
`, org, name, desc, name)
}

func testAccCredentialConfig_custom(org, name, desc string) string {
	return fmt.Sprintf(`
resource "cycloid_credential" "test" {
  organization_canonical = "%s"
  name                  = "%s"
  description           = "%s"
  type                  = "custom"
  path                  = "%s"
  
  body = {
    raw = {
      api_key    = "test-api-key"
      endpoint   = "https://api.example.com"
      secret_key = "test-secret-key"
    }
  }
}
`, org, name, desc, name)
}

func TestCredentialRawCYModelToDataBodyForCustomCredential(t *testing.T) {
	data := credentialResourceModel{}
	rawCredential := &models.CredentialRaw{
		Raw: map[string]string{
			"first_key":  "first_value",
			"second_key": "second_value",
		},
		Password: "password_value",
	}

	diags := credentialRawCYModelToDataBody(t.Context(), "custom", rawCredential, &data)
	if diags.HasError() {
		t.Fatalf("expected no diagnostics, got: %v", diags)
	}

	assert.Equal(t, "password_value", data.Body.Password.ValueString())
	assert.False(t, data.Body.Raw.IsNull(), "body.raw should be set for custom credentials")

	var rawValues map[string]types.String
	rawDiags := data.Body.Raw.ElementsAs(t.Context(), &rawValues, false)
	if rawDiags.HasError() {
		t.Fatalf("expected raw map conversion without diagnostics, got: %v", rawDiags)
	}

	assert.Equal(t, "first_value", rawValues["first_key"].ValueString())
	assert.Equal(t, "second_value", rawValues["second_key"].ValueString())
}

func TestCredentialRawCYModelToDataBodyForNonCustomCredential(t *testing.T) {
	data := credentialResourceModel{}
	rawCredential := &models.CredentialRaw{
		AccessKey: "access_key_value",
		Raw: map[string]string{
			"should_be_ignored": "ignored_value",
		},
	}

	diags := credentialRawCYModelToDataBody(t.Context(), "aws", rawCredential, &data)
	if diags.HasError() {
		t.Fatalf("expected no diagnostics, got: %v", diags)
	}

	assert.Equal(t, "access_key_value", data.Body.AccessKey.ValueString())
	assert.True(t, data.Body.Raw.IsNull(), "body.raw should be null for non-custom credentials")
}

func TestCredentialCanonicalForUpdate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		planCanonical  string
		stateCanonical string
		expected       string
	}{
		{
			name:           "uses state canonical when both are set",
			planCanonical:  "plan-canonical",
			stateCanonical: "state-canonical",
			expected:       "state-canonical",
		},
		{
			name:           "uses state canonical when plan is empty",
			planCanonical:  "",
			stateCanonical: "state-canonical",
			expected:       "state-canonical",
		},
		{
			name:           "uses plan canonical when state is empty",
			planCanonical:  "plan-canonical",
			stateCanonical: "",
			expected:       "plan-canonical",
		},
		{
			name:           "returns empty when both are empty",
			planCanonical:  "",
			stateCanonical: "",
			expected:       "",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			actual := credentialCanonicalForUpdate(testCase.planCanonical, testCase.stateCanonical)
			assert.Equal(t, testCase.expected, actual)
		})
	}
}

func TestCredentialCanonicalForCreate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		planCanonical  string
		stateCanonical string
		expected       string
	}{
		{
			name:           "uses plan canonical when both are set",
			planCanonical:  "plan-canonical",
			stateCanonical: "state-canonical",
			expected:       "plan-canonical",
		},
		{
			name:           "uses state canonical when plan is empty",
			planCanonical:  "",
			stateCanonical: "state-canonical",
			expected:       "state-canonical",
		},
		{
			name:           "uses plan canonical when state is empty",
			planCanonical:  "plan-canonical",
			stateCanonical: "",
			expected:       "plan-canonical",
		},
		{
			name:           "returns empty when both are empty",
			planCanonical:  "",
			stateCanonical: "",
			expected:       "",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			actual := credentialCanonicalForCreate(testCase.planCanonical, testCase.stateCanonical)
			assert.Equal(t, testCase.expected, actual)
		})
	}
}

func TestConfiguredCredentialOwner(t *testing.T) {
	testCases := []struct {
		name          string
		owner         types.String
		expectedOwner string
		expectedSet   bool
	}{
		{
			name:          "known owner",
			owner:         types.StringValue("alice"),
			expectedOwner: "alice",
			expectedSet:   true,
		},
		{
			name:          "empty owner",
			owner:         types.StringValue(""),
			expectedOwner: "",
			expectedSet:   false,
		},
		{
			name:          "null owner",
			owner:         types.StringNull(),
			expectedOwner: "",
			expectedSet:   false,
		},
		{
			name:          "unknown owner",
			owner:         types.StringUnknown(),
			expectedOwner: "",
			expectedSet:   false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			owner, set := configuredCredentialOwner(testCase.owner)
			assert.Equal(t, testCase.expectedOwner, owner)
			assert.Equal(t, testCase.expectedSet, set)
		})
	}
}

func TestResolveCredentialUpdateOwner(t *testing.T) {
	testCases := []struct {
		name        string
		configOwner types.String
		stateOwner  types.String
		expected    string
	}{
		{
			name:        "config owner takes precedence",
			configOwner: types.StringValue("configured-owner"),
			stateOwner:  types.StringValue("state-owner"),
			expected:    "configured-owner",
		},
		{
			name:        "state owner used when config owner missing",
			configOwner: types.StringNull(),
			stateOwner:  types.StringValue("state-owner"),
			expected:    "state-owner",
		},
		{
			name:        "empty when neither owner exists",
			configOwner: types.StringUnknown(),
			stateOwner:  types.StringNull(),
			expected:    "",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			owner := resolveCredentialUpdateOwner(testCase.configOwner, testCase.stateOwner)
			assert.Equal(t, testCase.expected, owner)
		})
	}
}

// TestCredentialSchemaCanonicalForcesReplaceWhenConfigured guards the fix for
// the "Provider produced inconsistent result after apply" bug on
// `.canonical`. The Cycloid API cannot cleanly rename a credential canonical
// (a PUT that changes it renames server-side but responds 404), so a changed,
// explicitly-configured canonical must force replacement rather than an
// in-place update. This is enforced by a RequiresReplaceIfConfigured plan
// modifier added in credentialResource.Schema(). The credential schema is
// code-generated, so this also protects the post-processing from being lost on
// regeneration.
func TestCredentialSchemaCanonicalForcesReplaceWhenConfigured(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resp := &fwresource.SchemaResponse{}
	NewCredentialResource().Schema(ctx, fwresource.SchemaRequest{}, resp)

	attr, ok := resp.Schema.Attributes["canonical"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("canonical attribute is not a schema.StringAttribute: %T", resp.Schema.Attributes["canonical"])
	}

	found := false
	for _, pm := range attr.PlanModifiers {
		if strings.Contains(pm.Description(ctx), "destroy and recreate") {
			found = true
			break
		}
	}
	assert.True(t, found, "canonical must force replacement when a configured value changes; the API cannot rename a credential canonical in place")
}
