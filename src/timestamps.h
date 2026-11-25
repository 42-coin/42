#ifndef BITCOIN_TIMESTAMPS_H
#define BITCOIN_TIMESTAMPS_H
static const unsigned int CHECKLOCKTIMEVERIFY_SWITCH_TIME = 1478476800; // Monday, 07 Nov 2016 00:00:00 UTC
static const unsigned int CHECKSEQUENCEVERIFY_SWITCH_TIME = 1740225600; // Saturday, 22 Feb 2025 12:00:00 UTC

// Activation of the post-quantum (Falcon-512) rules by wall-clock time, like the
// CHECKLOCKTIMEVERIFY/CHECKSEQUENCEVERIFY switches above: STRICT_FALCON_SWITCH_TIME turns on
// consensus Falcon-512 signature verification inside strict falcon scripts, FALCON_ZONE_SWITCH_TIME
// requires every spend to go through such scripts (see W3). Both are soft-fork switches.
// Testnet is active immediately (switch date in the past) so it launches first.
static const unsigned int STRICT_FALCON_SWITCH_TIME = 1798761600;         // Friday, 01 Jan 2027 00:00:00 UTC
static const unsigned int STRICT_FALCON_SWITCH_TIME_TESTNET = 1767225600; // Thursday, 01 Jan 2026 00:00:00 UTC
static const unsigned int FALCON_ZONE_SWITCH_TIME = 1798761600;         // Friday, 01 Jan 2027 00:00:00 UTC
static const unsigned int FALCON_ZONE_SWITCH_TIME_TESTNET = 1767225600; // Thursday, 01 Jan 2026 00:00:00 UTC

// From this common wall-clock date the transaction fees are burned in proof-of-work
// blocks exactly like they always were in proof-of-stake blocks: the coinbase pays
// the subsidy only and the fees leave the money supply. The same date applies to
// both networks.
static const unsigned int FEE_BURN_SWITCH_TIME = 1798761600;         // Friday, 01 Jan 2027 00:00:00 UTC
static const unsigned int FEE_BURN_SWITCH_TIME_TESTNET = 1798761600; // Friday, 01 Jan 2027 00:00:00 UTC
// Threshold for nLockTime: below this value it is interpreted as block number, otherwise as UNIX timestamp.
static const unsigned int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC
#endif
