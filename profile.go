package main

import "fmt"

type deviceFamilyProfile struct {
	Product, Board   string
	CPID, BDID, CPFM uint64
}

func (p deviceFamilyProfile) matches(d device) bool {
	return d.CPID == p.CPID && d.BDID == p.BDID && d.CPFM == p.CPFM
}

type siliconProfile struct {
	Name                        string
	CPID, LoaderLow, LoaderHigh uint64
}

type artifactIdentity struct {
	DecodedSize   int
	DecodedSHA256 string
}

type rootSelectionProfile struct {
	BootArguments string
	RootArguments string
}

type runtimeProfile struct {
	ID, IOSVersion, OSBuild, LoaderBuild string
	IBEC, Kernel                         artifactIdentity
	Root                                 rootSelectionProfile
}

var supportedFamily = deviceFamilyProfile{
	Product: "iPhone15,5", Board: "d38ap", CPID: 0x8120, BDID: 0x0a, CPFM: 0,
}

var siliconProfiles = []siliconProfile{{
	Name: "t8120", CPID: 0x8120, LoaderLow: 0x1fc000000, LoaderHigh: 0x1fd000000,
}}

var canonicalRuntime = runtimeProfile{
	ID: "d38ap-23D127", IOSVersion: "26.3", OSBuild: "23D127", LoaderBuild: "iBoot-13822.82.4",
	IBEC:   artifactIdentity{DecodedSize: 2455216, DecodedSHA256: "eb62ecd0a656dfbd45fddbe3200e650baefe95837bab3270021d51dd88e91391"},
	Kernel: artifactIdentity{DecodedSize: 65421312, DecodedSHA256: "017f72f9c31266c707d94880a531cb31e755300c8e17dc7d1a748c13d567f86a"},
	Root: rootSelectionProfile{
		BootArguments: "-v serial=3 debug=0x14e keepsyms=1",
		RootArguments: "-v rd=md0 serial=3 debug=0x14e",
	},
}

func siliconFor(d device) (siliconProfile, error) {
	for _, profile := range siliconProfiles {
		if profile.CPID == d.CPID {
			return profile, nil
		}
	}
	return siliconProfile{}, fmt.Errorf("no debug topology for CPID %04X", d.CPID)
}
