package oidc //nolint:testpackage

import (
	"context"
	"log"
)

var (
	Export_validateAudience          = validateAudience
	Export_appleConfigurationURI     = appleConfigurationURI
	Export_googleConfigurationURI    = googleConfigurationURI
	Export_makeADB2CConfigurationURI = makeADB2CConfigurationURI

	// Deprecated: Use Export_appleConfigurationURI instead.
	Export_appleCoinfigurationURI = appleConfigurationURI
	// Deprecated: Use Export_googleConfigurationURI instead.
	Export_googleCoinfigurationURI = googleConfigurationURI
)

func CheckCache(cfguri string) bool {
	muxPM.RLock()
	defer muxPM.RUnlock()

	cfg, ok := cacheProviderMeta[cfguri]
	if !ok {
		log.Printf("cacheProviderMeta: %s not found in cache", cfguri)
		return false
	}

	cache, err := getJWKCache()
	if err != nil {
		return false
	}

	return cache.IsRegistered(context.Background(), cfg.JWKSURI)
}
