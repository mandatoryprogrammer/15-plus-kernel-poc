package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const runtimeQualificationSchema = "15-plus-kernel-poc.runtime-qualification.v1"

type runtimeQualifiedRole struct {
	Role   string `json:"role"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type runtimeQualifiedTrust struct {
	SHA256        string `json:"sha256"`
	Version       uint32 `json:"version"`
	SystemEntries int    `json:"system_entries"`
	BaseEntries   int    `json:"base_entries"`
	MergedEntries int    `json:"merged_entries"`
}

type runtimeQualifiedUI struct {
	Schema         string    `json:"schema"`
	Files          int       `json:"files"`
	LauncherSHA256 string    `json:"launcher_sha256"`
	Program        uiProgram `json:"program"`
	ProductVersion string    `json:"product_version"`
	ProductBuild   string    `json:"product_build"`
}

type runtimeQualifiedRoot struct {
	IndexSHA256      string `json:"index_sha256"`
	ProductVersion   string `json:"product_version"`
	ProductBuild     string `json:"product_build"`
	Executables      int    `json:"executables"`
	Plists           int    `json:"plists"`
	MachServices     int    `json:"mach_services"`
	SharedCaches     int    `json:"shared_caches"`
	TrustCaches      int    `json:"static_trust_caches"`
	SharedCacheState string `json:"shared_cache_state"`
	SystemTrustState string `json:"system_trust_state"`
}

type runtimeQualificationReport struct {
	Schema               string                 `json:"schema"`
	Qualified            bool                   `json:"qualified"`
	StartedAt            string                 `json:"started_at"`
	FinishedAt           string                 `json:"finished_at"`
	RuntimeID            string                 `json:"runtime_id"`
	IOSVersion           string                 `json:"ios_version"`
	OSBuild              string                 `json:"os_build"`
	LoaderBuild          string                 `json:"loader_build"`
	PreparedRoles        []runtimeQualifiedRole `json:"prepared_roles,omitempty"`
	SystemTrust          *runtimeQualifiedTrust `json:"system_trust,omitempty"`
	UI                   *runtimeQualifiedUI    `json:"ui,omitempty"`
	AdmissionFingerprint string                 `json:"admission_fingerprint,omitempty"`
	ProductOSRoot        *runtimeQualifiedRoot  `json:"productos_root,omitempty"`
	Error                string                 `json:"error,omitempty"`
}

func runtimeCommand(ctx context.Context, c *cache, args []string) error {
	if len(args) >= 1 && args[0] == "qualify" {
		return runtimeQualifyCommand(ctx, c, args[1:])
	}
	return errors.New("usage: runtime qualify [PRODUCTOS_ROOT]")
}

func runtimeQualifyCommand(ctx context.Context, c *cache, args []string) error {
	if len(args) > 1 {
		return errors.New("usage: runtime qualify [PRODUCTOS_ROOT]")
	}
	root := ""
	if len(args) == 1 {
		root = args[0]
	}
	report, err := qualifyRuntime(ctx, c, root)
	if err != nil {
		return err
	}
	rootText := ""
	if report.ProductOSRoot != nil {
		rootText = fmt.Sprintf(", ProductOS index %s", report.ProductOSRoot.IndexSHA256)
	}
	fmt.Fprintf(c.out, "Runtime %s qualified: %d exact prepared roles, complete system trust %s, UI profile %s, admission %s%s\n",
		report.RuntimeID, len(report.PreparedRoles), report.SystemTrust.SHA256, report.UI.Schema, report.AdmissionFingerprint, rootText)
	return nil
}

func qualifyRuntime(ctx context.Context, c *cache, productRoot string) (runtimeQualificationReport, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	fmt.Fprintln(c.out, "Qualifying pinned runtime, complete system trust, UI profile, and admission fingerprint (deadline 2h)")
	stop := heartbeat(c.out, "Qualifying coherent runtime", 2*time.Hour)
	defer stop()
	report := runtimeQualificationReport{
		Schema:      runtimeQualificationSchema,
		StartedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		RuntimeID:   canonicalRuntime.ID,
		IOSVersion:  canonicalRuntime.IOSVersion,
		OSBuild:     canonicalRuntime.OSBuild,
		LoaderBuild: canonicalRuntime.LoaderBuild,
	}
	qualifyErr := qualifyRuntimeInto(ctx, c, productRoot, &report)
	if qualifyErr == nil {
		report.Qualified = true
	} else {
		report.Error = qualifyErr.Error()
	}
	report.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if writeErr := writeRuntimeQualification(c, report); writeErr != nil {
		if qualifyErr != nil {
			return report, errors.Join(qualifyErr, fmt.Errorf("write runtime qualification report: %w", writeErr))
		}
		return report, writeErr
	}
	return report, qualifyErr
}

func qualifyRuntimeInto(ctx context.Context, c *cache, productRoot string, report *runtimeQualificationReport) error {
	runtimeRoles := map[string]bool{"ibec": true, "ramdisk": true, "kernel": true, "sptm": true, "txm": true, "trust-cache": true}
	rows, err := preparedSet("runtime", runtimeRoles)
	if err != nil {
		return fmt.Errorf("prepared runtime descriptor: %w", err)
	}
	var baseAsset asset
	for _, row := range rows {
		if err = verifyFile(ctx, c.object(row), row); err != nil {
			return fmt.Errorf("verify prepared runtime role %s: %w", row.Role, err)
		}
		report.PreparedRoles = append(report.PreparedRoles, runtimeQualifiedRole{Role: row.Role, SHA256: row.SHA256, Size: row.Size})
		if row.Role == "trust-cache" {
			baseAsset = row
		}
	}
	sort.Slice(report.PreparedRoles, func(i, j int) bool { return report.PreparedRoles[i].Role < report.PreparedRoles[j].Role })
	if baseAsset.Role == "" {
		return errors.New("prepared runtime has no base trust cache")
	}
	baseBody, err := os.ReadFile(c.object(baseAsset))
	if err != nil {
		return err
	}
	base, err := parseTrustCacheImage(baseBody, "rtsc")
	if err != nil {
		return fmt.Errorf("prepared runtime base trust cache: %w", err)
	}
	systemDescriptor, systemBody, err := loadSystemTrustContext(ctx, c)
	if err != nil {
		return fmt.Errorf("complete system trust context: %w", err)
	}
	if systemDescriptor == nil {
		return errors.New("complete system trust context is not configured; import ProductOS StaticTrustCache first")
	}
	_, mergedEntries, err := mergeSystemTrustCache(baseBody, systemBody)
	if err != nil {
		return fmt.Errorf("complete system trust context is incompatible with prepared runtime: %w", err)
	}
	report.SystemTrust = &runtimeQualifiedTrust{
		SHA256: systemDescriptor.Object.SHA256, Version: systemDescriptor.Version,
		SystemEntries: systemDescriptor.EntryCount, BaseEntries: len(base.rows), MergedEntries: mergedEntries,
	}

	profile, err := loadUIProfile(ctx, c)
	if err != nil {
		return fmt.Errorf("UI profile: %w", err)
	}
	if profile.Schema != "15-plus-kernel-poc.ui-profile.v3" || profile.Launcher == nil || profile.Program == nil {
		return errors.New("UI profile needs an exact ProductOS root launcher and active program")
	}
	uiSystemVersion, err := uiObjectPath(c, profile, "System/Library/CoreServices/SystemVersion.plist")
	if err != nil {
		return err
	}
	uiSystemBody, err := os.ReadFile(uiSystemVersion)
	if err != nil {
		return err
	}
	uiValues, err := decodeTargetPlist(uiSystemBody)
	if err != nil {
		return fmt.Errorf("UI SystemVersion.plist: %w", err)
	}
	uiVersion, versionOK := uiValues["ProductVersion"].(string)
	uiBuild, buildOK := uiValues["ProductBuildVersion"].(string)
	if !versionOK || !buildOK || uiVersion == "" || uiBuild == "" {
		return errors.New("UI profile SystemVersion.plist has no ProductVersion/ProductBuildVersion")
	}
	report.UI = &runtimeQualifiedUI{
		Schema: profile.Schema, Files: len(profile.Files), LauncherSHA256: profile.Launcher.SHA256,
		Program:        *profile.Program,
		ProductVersion: uiVersion, ProductBuild: uiBuild,
	}

	report.AdmissionFingerprint, err = payloadAdmissionFingerprint(ctx, c)
	if err != nil {
		return fmt.Errorf("admission fingerprint: %w", err)
	}
	if productRoot == "" {
		return nil
	}
	absoluteRoot, err := filepath.Abs(productRoot)
	if err != nil {
		return err
	}
	index, err := buildTargetIndexWithOutput(ctx, absoluteRoot, c.out)
	if err != nil {
		return fmt.Errorf("ProductOS root: %w", err)
	}
	if index.ProductVersion != canonicalRuntime.IOSVersion || index.ProductBuild != canonicalRuntime.OSBuild {
		return fmt.Errorf("ProductOS root build %s/%s does not match runtime %s/%s", index.ProductVersion, index.ProductBuild, canonicalRuntime.IOSVersion, canonicalRuntime.OSBuild)
	}
	if len(index.StaticTrustCaches) != 0 && !targetIndexTrustMatches(index, systemBody) {
		return errors.New("ProductOS root StaticTrustCache does not match the configured complete system trust context")
	}
	artifact, err := storeTargetIndex(c, index)
	if err != nil {
		return fmt.Errorf("store ProductOS target index: %w", err)
	}
	sharedCacheState := "present-in-system-volume"
	if len(index.SharedCaches) == 0 {
		sharedCacheState = "external-to-system-volume"
	}
	systemTrustState := "matches-configured-complete-context"
	if len(index.StaticTrustCaches) == 0 {
		systemTrustState = "configured-complete-context-external-to-system-volume"
	}
	report.ProductOSRoot = &runtimeQualifiedRoot{
		IndexSHA256: artifact.SHA256, ProductVersion: index.ProductVersion, ProductBuild: index.ProductBuild,
		Executables: len(index.Executables), Plists: len(index.Plists), MachServices: len(index.MachServices),
		SharedCaches: len(index.SharedCaches), TrustCaches: len(index.StaticTrustCaches),
		SharedCacheState: sharedCacheState, SystemTrustState: systemTrustState,
	}
	return nil
}

func writeRuntimeQualification(c *cache, report runtimeQualificationReport) error {
	if report.Schema != runtimeQualificationSchema || report.RuntimeID == "" || report.StartedAt == "" || report.FinishedAt == "" {
		return errors.New("invalid runtime qualification report")
	}
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	name := filepath.Join(c.root, "private", "runtime-qualify-latest.json")
	f, err := os.CreateTemp(filepath.Dir(name), "runtime-qualify-")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(body)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporary, name)
}

func targetIndexTrustMatches(index targetIndex, configuredIM4P []byte) bool {
	want := digest(configuredIM4P)
	for _, trust := range index.StaticTrustCaches {
		if trust.ImageSHA256 == want {
			return true
		}
	}
	return false
}
