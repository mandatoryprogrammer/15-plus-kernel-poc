package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const serviceChainProfileSchema = "15-plus-kernel-poc.service-chain-profile.v1"

type serviceChainProfileInput struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type serviceChainProfile struct {
	Schema               string                    `json:"schema"`
	Name                 string                    `json:"name"`
	Manifest             serviceChainProfileInput  `json:"manifest"`
	Launcher             *serviceChainProfileInput `json:"launcher,omitempty"`
	ProgramArgv0         string                    `json:"program_argv0,omitempty"`
	PreservedNative      *serviceChainProfileInput `json:"preserved_native,omitempty"`
	PreservedDestination string                    `json:"preserved_destination,omitempty"`
	SystemOSCryptex      *serviceChainProfileInput `json:"systemos_cryptex,omitempty"`
	SystemOSTrust        *serviceChainProfileInput `json:"systemos_trust_cache,omitempty"`
}

func serviceChainProfileDirectory(c *cache) string {
	return filepath.Join(c.root, "private", "service-chain-profiles")
}

func serviceChainProfileInputFor(path string) (serviceChainProfileInput, error) {
	abs, size, sha, err := readRegularIdentity(path)
	return serviceChainProfileInput{Path: abs, Bytes: size, SHA256: sha}, err
}

func verifyServiceChainProfileInput(input *serviceChainProfileInput) error {
	if input == nil {
		return nil
	}
	path, size, sha, err := readRegularIdentity(input.Path)
	if err != nil {
		return err
	}
	if path != input.Path || size != input.Bytes || sha != input.SHA256 {
		return fmt.Errorf("profile input changed: %s", input.Path)
	}
	return nil
}

func serviceChainProfileCommand(_ context.Context, c *cache, args []string) error {
	if len(args) == 2 && args[0] == "show" {
		profile, ok, err := loadServiceChainProfile(c, args[1])
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("unknown service-chain profile %q", args[1])
		}
		body, _ := json.MarshalIndent(profile, "", "  ")
		fmt.Fprintf(c.out, "%s\n", body)
		return nil
	}
	if len(args) < 4 || args[0] != "bind" {
		return errors.New("usage: service-chain profile bind NAME --manifest FILE [--launcher FILE] [--program-argv0 PATH] [--preserve-native FILE=DEST] [--systemos-cryptex IMAGE --systemos-cryptex-trust-cache FILE] | service-chain profile show NAME")
	}
	name := args[1]
	if !machServiceName.MatchString(name) {
		return errors.New("profile name must contain only letters, digits, dot, underscore, or hyphen")
	}
	profile := serviceChainProfile{Schema: serviceChainProfileSchema, Name: name}
	var manifest, launcher, programArgv0, native, cryptex, trust, destination string
	for index := 2; index < len(args); index++ {
		if index+1 >= len(args) {
			return fmt.Errorf("%s needs a value", args[index])
		}
		option, value := args[index], args[index+1]
		index++
		switch option {
		case "--manifest":
			if manifest != "" {
				return errors.New("--manifest may appear once")
			}
			manifest = value
		case "--launcher":
			if launcher != "" {
				return errors.New("--launcher may appear once")
			}
			launcher = value
		case "--program-argv0":
			if programArgv0 != "" {
				return errors.New("--program-argv0 may appear once")
			}
			if !validUIArgv0(value) {
				return errors.New("--program-argv0 must be a clean absolute target path")
			}
			programArgv0 = value
		case "--preserve-native":
			if native != "" {
				return errors.New("--preserve-native may appear once")
			}
			var err error
			native, destination, err = splitPayloadInclude(value)
			if err != nil {
				return err
			}
		case "--systemos-cryptex":
			if cryptex != "" {
				return errors.New("--systemos-cryptex may appear once")
			}
			cryptex = value
		case "--systemos-cryptex-trust-cache":
			if trust != "" {
				return errors.New("--systemos-cryptex-trust-cache may appear once")
			}
			trust = value
		default:
			return fmt.Errorf("unknown service-chain profile option %q", option)
		}
	}
	if manifest == "" {
		return errors.New("profile requires --manifest FILE")
	}
	if (cryptex == "") != (trust == "") {
		return errors.New("profile SystemOS cryptex and trust cache must be supplied together")
	}
	if _, _, err := loadServiceChainManifest(manifest); err != nil {
		return err
	}
	var err error
	if profile.Manifest, err = serviceChainProfileInputFor(manifest); err != nil {
		return err
	}
	profile.ProgramArgv0 = programArgv0
	if launcher != "" {
		value, inputErr := serviceChainProfileInputFor(launcher)
		if inputErr != nil {
			return inputErr
		}
		profile.Launcher = &value
	}
	if native != "" {
		value, inputErr := serviceChainProfileInputFor(native)
		if inputErr != nil {
			return inputErr
		}
		profile.PreservedNative = &value
		profile.PreservedDestination = destination
	}
	if cryptex != "" {
		cryptexValue, inputErr := serviceChainProfileInputFor(cryptex)
		if inputErr != nil {
			return inputErr
		}
		trustValue, inputErr := serviceChainProfileInputFor(trust)
		if inputErr != nil {
			return inputErr
		}
		profile.SystemOSCryptex = &cryptexValue
		profile.SystemOSTrust = &trustValue
	}
	directory := serviceChainProfileDirectory(c)
	if err = os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	path := filepath.Join(directory, name+".json")
	if err = writeProbeFile(path, body, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Bound service-chain profile %s profile_sha256=%s profile=%s\n", name, digest(body), path)
	return nil
}

func loadServiceChainProfile(c *cache, name string) (serviceChainProfile, bool, error) {
	var profile serviceChainProfile
	if !machServiceName.MatchString(name) {
		return profile, false, nil
	}
	path := filepath.Join(serviceChainProfileDirectory(c), name+".json")
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return profile, false, nil
	}
	if err != nil {
		return profile, false, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&profile); err != nil {
		return profile, false, err
	}
	if profile.Schema != serviceChainProfileSchema || profile.Name != name {
		return profile, false, errors.New("invalid service-chain profile")
	}
	if profile.ProgramArgv0 != "" && !validUIArgv0(profile.ProgramArgv0) {
		return profile, false, errors.New("invalid service-chain profile program argv0")
	}
	for _, input := range []*serviceChainProfileInput{&profile.Manifest, profile.Launcher, profile.PreservedNative, profile.SystemOSCryptex, profile.SystemOSTrust} {
		if err = verifyServiceChainProfileInput(input); err != nil {
			return profile, false, err
		}
	}
	if _, _, err = loadServiceChainManifest(profile.Manifest.Path); err != nil {
		return profile, false, err
	}
	return profile, true, nil
}

func extractServiceChainProgram(args []string) ([]string, string, error) {
	var result []string
	var program string
	for index := 0; index < len(args); index++ {
		if args[index] == "--" {
			result = append(result, args[index:]...)
			break
		}
		if args[index] == "--program" {
			if program != "" || index+1 >= len(args) {
				return nil, "", errors.New("service-chain run accepts exactly one --program FILE")
			}
			program = args[index+1]
			index++
			continue
		}
		result = append(result, args[index])
	}
	return result, program, nil
}

type serviceChainReducedEvidence struct {
	Schema         string             `json:"schema"`
	Outcome        string             `json:"outcome"`
	ChainReady     bool               `json:"chain_ready"`
	ProgramReached bool               `json:"program_reached"`
	CleanupExact   bool               `json:"cleanup_exact"`
	Identities     map[string]string  `json:"identities"`
	Markers        []string           `json:"markers,omitempty"`
	Run            serviceChainReport `json:"run"`
	Payload        *payloadRunReport  `json:"payload,omitempty"`
}

func reduceServiceChainEvidence(c *cache, report serviceChainReport) error {
	report.ProgramReached = report.ProgramReached ||
		markerContains(report.Markers, "PRODUCT_SERVICE_CHAIN stage=hidd-producer-probe-spawn") ||
		markerContains(report.Markers, "CAR_LOGICAL_BOUNDS_SUPERVISOR stage=invocation")
	evidence := serviceChainReducedEvidence{Schema: "15-plus-kernel-poc.service-chain-evidence.v1", Outcome: "failed-before-program", ChainReady: report.ChainReady, ProgramReached: report.ProgramReached, CleanupExact: report.RecoveryCleanup == "" || report.RecoveryCleanup == "persistent-recovery-verified", Markers: append([]string(nil), report.Markers...), Run: report, Identities: map[string]string{"manifest": report.ManifestSHA256, "program": report.Program.SHA256}}
	if report.ProgramReached {
		evidence.Outcome = "program-failed"
	}
	if report.Exit == "zero" {
		evidence.Outcome = "zero-exit"
	}
	if report.SystemOSCryptex != nil {
		evidence.Identities["systemos_cryptex"] = report.SystemOSCryptex.SHA256
		evidence.Identities["systemos_trust_cache"] = report.SystemOSCryptex.TrustCacheSHA256
	}
	payloadBody, err := os.ReadFile(filepath.Join(c.root, "private", "payload-run-latest.json"))
	if err == nil {
		var payload payloadRunReport
		if json.Unmarshal(payloadBody, &payload) == nil {
			evidence.Payload = &payload
			evidence.Identities["payload"] = payload.SHA256
			evidence.Identities["admission"] = payload.AdmissionFingerprint
		}
	}
	body, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err = writeProbeFile(filepath.Join(c.root, "private", "service-chain-evidence-latest.json"), body, 0o600); err != nil {
		return err
	}
	directory := filepath.Join(c.root, "private", "service-chain-evidence")
	if err = os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	identity := digest(body)
	if err = writeProbeFile(filepath.Join(directory, identity+".json"), body, 0o600); err != nil {
		return err
	}
	entries, _ := os.ReadDir(directory)
	for _, entry := range entries {
		if !entry.IsDir() && entry.Name() != identity+".json" && strings.HasSuffix(entry.Name(), ".json") {
			_ = os.Remove(filepath.Join(directory, entry.Name()))
		}
	}
	fmt.Fprintf(c.out, "Reduced service-chain evidence outcome=%s cleanup_exact=%t sha256=%s evidence=%s\n", evidence.Outcome, evidence.CleanupExact, identity, filepath.Join(c.root, "private", "service-chain-evidence-latest.json"))
	return nil
}

func evidenceCommand(c *cache, args []string) error {
	if len(args) != 1 || args[0] != "reduce" {
		return errors.New("usage: evidence reduce")
	}
	body, err := os.ReadFile(filepath.Join(c.root, "private", "service-chain-run-latest.json"))
	if err != nil {
		return err
	}
	var report serviceChainReport
	if err = json.Unmarshal(body, &report); err != nil {
		return err
	}
	return reduceServiceChainEvidence(c, report)
}
