// SPDX-License-Identifier: GPL-2.0-or-later
/* E-VPN header for packet handling
 * Copyright (C) 2016 6WIND
 */
#include "bgpd.h"

extern int bgp_nlri_parse_mpte(struct peer *peer, struct attr *attr,
			struct bgp_nlri *packet, bool withdraw);