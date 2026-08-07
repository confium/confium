// Terraform provider for Confium threshold cryptography.
//
// Resources:
//   - confium_threshold_key: generate + manage a threshold keyset
//   - confium_signing_ceremony: trigger a threshold signing ceremony
//   - confium_transparency_log: manage a log.confium.org endpoint
//   - confium_share: manage individual share blobs

package main

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func main() {
	provider.Serve(context.Background(), NewConfiumProvider, provider.ServeOpts{})
}

type ConfiumProvider struct {
	version string
}

type ConfiumProviderModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	APIToken types.String `tfsdk:"api_token"`
}

func NewConfiumProvider() provider.Provider {
	return &ConfiumProvider{version: "0.1.0"}
}

func (p *ConfiumProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "confium"
	resp.Version = p.version
}

func (p *ConfiumProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Description: "URL of the Confium coordinator endpoint.",
				Optional:    true,
			},
			"api_token": schema.StringAttribute{
				Description: "API token for the Confium coordinator.",
				Optional:    true,
				Sensitive:   true,
			},
		},
	}
}

func (p *ConfiumProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewThresholdKeyResource,
		NewSigningCeremonyResource,
	}
}

func (p *ConfiumProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewTransparencyLogDataSource,
	}
}

// Resource scaffolds

type ThresholdKeyResource struct{}

func NewThresholdKeyResource() resource.Resource { return &ThresholdKeyResource{} }

func (r *ThresholdKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_threshold_key"
}

func (r *ThresholdKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id":           schema.StringAttribute{Computed: true},
			"scheme":       schema.StringAttribute{Required: true},
			"threshold":    schema.Int64Attribute{Required: true},
			"party_count":  schema.Int64Attribute{Required: true},
			"public_key":   schema.StringAttribute{Computed: true, Sensitive: true},
			"shares":       schema.ListAttribute{ElementType: types.StringType, Computed: true, Sensitive: true},
		},
	}
}

func (r *ThresholdKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Calls the Confium coordinator to run threshold DKG.
	fmt.Fprintln(nil, "threshold_key.create")
}

func (r *ThresholdKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {}
func (r *ThresholdKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {}
func (r *ThresholdKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {}

type SigningCeremonyResource struct{}

func NewSigningCeremonyResource() resource.Resource { return &SigningCeremonyResource{} }

func (r *SigningCeremonyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_signing_ceremony"
}

func (r *SigningCeremonyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id":         schema.StringAttribute{Computed: true},
			"scheme":     schema.StringAttribute{Required: true},
			"threshold":  schema.Int64Attribute{Required: true},
			"shares":     schema.ListAttribute{ElementType: types.StringType, Required: true, Sensitive: true},
			"message":    schema.StringAttribute{Required: true},
			"signature":  schema.StringAttribute{Computed: true},
			"public_key": schema.StringAttribute{Required: true},
		},
	}
}

func (r *SigningCeremonyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Calls the Confium coordinator to run threshold signing.
}
func (r *SigningCeremonyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse)   {}
func (r *SigningCeremonyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {}
func (r *SigningCeremonyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {}

// DataSource scaffolds

type TransparencyLogDataSource struct{}

func NewTransparencyLogDataSource() datasource.DataSource { return &TransparencyLogDataSource{} }

func (d *TransparencyLogDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_transparency_log"
}

func (d *TransparencyLogDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{Required: true},
			"tree_size": schema.Int64Attribute{Computed: true},
			"root":      schema.StringAttribute{Computed: true},
		},
	}
}

func (d *TransparencyLogDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	// Fetches /v1/head from log.confium.org.
}
