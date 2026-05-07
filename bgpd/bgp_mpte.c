// SPDX-License-Identifier: GPL-2.0-or-later
/* Ethernet-VPN Packet and vty Processing File
 * Copyright (C) 2016 6WIND
 * Copyright (C) 2017 Cumulus Networks, Inc.
 */

#include <zebra.h>

#include "command.h"
#include "filter.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"
#include "hash.h"
#include "jhash.h"
#include "zclient.h"

#include "lib/printfrr.h"

#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_mpte.h"
// #include "bgpd/bgp_mpte_private.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_encap_types.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_mac.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_trace.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_packet.h"

/*
 * Definitions and external declarations.
 
DEFINE_QOBJ_TYPE(bgpevpn);
DEFINE_QOBJ_TYPE(bgp_evpn_es);

DEFINE_MTYPE_STATIC(BGPD, BGP_EVPN_INFO, "BGP EVPN instance information");
DEFINE_MTYPE_STATIC(BGPD, VRF_ROUTE_TARGET, "L3 Route Target");


 * Static function declarations
 
static void bgp_evpn_remote_ip_hash_init(struct bgpevpn *evpn);
static void bgp_evpn_remote_ip_hash_destroy(struct bgpevpn *evpn);
static void bgp_evpn_remote_ip_hash_add(struct bgpevpn *vpn,
					struct bgp_path_info *pi);
static void bgp_evpn_remote_ip_hash_del(struct bgpevpn *vpn,
					struct bgp_path_info *pi);
static void bgp_evpn_remote_ip_hash_iterate(struct bgpevpn *vpn,
					    void (*func)(struct hash_bucket *,
							 void *),
					    void *arg);
static void bgp_evpn_link_to_vni_svi_hash(struct bgp *bgp, struct bgpevpn *vpn);
static void bgp_evpn_unlink_from_vni_svi_hash(struct bgp *bgp,
					      struct bgpevpn *vpn);
static unsigned int vni_svi_hash_key_make(const void *p);
static bool vni_svi_hash_cmp(const void *p1, const void *p2);
static void bgp_evpn_remote_ip_process_nexthops(struct bgpevpn *vpn,
						struct ipaddr *addr,
						bool resolve);
static void bgp_evpn_remote_ip_hash_link_nexthop(struct hash_bucket *bucket,
						 void *args);
static void bgp_evpn_remote_ip_hash_unlink_nexthop(struct hash_bucket *bucket,
						   void *args);
static struct in_addr zero_vtep_ip;

static uint32_t bgp_evpn_addpath_id_for_path(const struct bgp *bgp, const struct bgp_path_info *pi,
					     afi_t afi);
*/

/*
 * Private functions.
 */


/*
 * Is specified VRF present on the RT's list of "importing" VRFs?
 */
// static int is_vrf_present_in_irt_vrfs(struct list *vrfs, struct bgp *bgp_vrf)
// {
// 	struct listnode *node = NULL, *nnode = NULL;
// 	struct bgp *tmp_bgp_vrf = NULL;

// 	for (ALL_LIST_ELEMENTS(vrfs, node, nnode, tmp_bgp_vrf)) {
// 		if (tmp_bgp_vrf == bgp_vrf)
// 			return 1;
// 	}
// 	return 0;
// }

// /*
//  * Make import route target hash key.
//  */
// static unsigned int import_rt_hash_key_make(const void *p)
// {
// 	const struct irt_node *irt = p;
// 	const uint8_t *pnt = irt->rt.val;

// 	return jhash(pnt, 8, 0xdeadbeef);
// }

// /*
//  * Comparison function for import rt hash
//  */
// static bool import_rt_hash_cmp(const void *p1, const void *p2)
// {
// 	const struct irt_node *irt1 = p1;
// 	const struct irt_node *irt2 = p2;

// 	return (memcmp(irt1->rt.val, irt2->rt.val, ECOMMUNITY_SIZE) == 0);
// }

// /*
//  * Create a new import_rt
//  */
// static struct irt_node *import_rt_new(struct bgp *bgp,
// 				      struct ecommunity_val *rt)
// {
// 	struct irt_node *irt;

// 	irt = XCALLOC(MTYPE_BGP_EVPN_IMPORT_RT, sizeof(struct irt_node));

// 	irt->rt = *rt;
// 	irt->vnis = list_new();

// 	/* Add to hash */
// 	(void)hash_get(bgp->import_rt_hash, irt, hash_alloc_intern);

// 	return irt;
// }

// /*
//  * Free the import rt node
//  */
// static void import_rt_free(struct bgp *bgp, struct irt_node *irt)
// {
// 	hash_release(bgp->import_rt_hash, irt);
// 	list_delete(&irt->vnis);
// 	XFREE(MTYPE_BGP_EVPN_IMPORT_RT, irt);
// }

// static void hash_import_rt_free(struct irt_node *irt)
// {
// 	XFREE(MTYPE_BGP_EVPN_IMPORT_RT, irt);
// }

// /*
//  * Function to lookup Import RT node - used to map a RT to set of
//  * VNIs importing routes with that RT.
//  */
// static struct irt_node *lookup_import_rt(struct bgp *bgp,
// 					 struct ecommunity_val *rt)
// {
// 	struct irt_node *irt;
// 	struct irt_node tmp;

// 	memset(&tmp, 0, sizeof(tmp));
// 	memcpy(&tmp.rt, rt, ECOMMUNITY_SIZE);
// 	irt = hash_lookup(bgp->import_rt_hash, &tmp);
// 	return irt;
// }

// /*
//  * Is specified VNI present on the RT's list of "importing" VNIs?
//  */
// static int is_vni_present_in_irt_vnis(struct list *vnis, struct bgpevpn *vpn)
// {
// 	struct listnode *node, *nnode;
// 	struct bgpevpn *tmp_vpn;

// 	for (ALL_LIST_ELEMENTS(vnis, node, nnode, tmp_vpn)) {
// 		if (tmp_vpn == vpn)
// 			return 1;
// 	}

// 	return 0;
// }

// /* Flag if the route is injectable into EVPN.
//  * This would be following category:
//  * Non-imported route,
//  * Non-EVPN imported route,
//  */
// bool is_route_injectable_into_evpn_non_supp(struct bgp_path_info *pi)
// {
// 	struct bgp_path_info *parent_pi;
// 	struct bgp_table *table;
// 	struct bgp_dest *dest;

// 	if (pi->sub_type != BGP_ROUTE_IMPORTED || !pi->extra ||
// 	    !pi->extra->vrfleak || !pi->extra->vrfleak->parent)
// 		return true;

//         parent_pi = (struct bgp_path_info *)pi->extra->vrfleak->parent;
//         dest = parent_pi->net;
//         if (!dest)
// 		return true;
//         table = bgp_dest_table(dest);
//         if (table &&
//             table->afi == AFI_L2VPN &&
//             table->safi == SAFI_EVPN)
//                 return false;

//         return true;
// }

// /* Flag if the route is injectable into EVPN.
//  * This would be following category:
//  * Non-imported route,
//  * Non-EVPN imported route,
//  * Non Aggregate suppressed route.
//  */
// bool is_route_injectable_into_evpn(struct bgp_path_info *pi)
// {
// 	/* do not import aggr suppressed routes */
// 	if (bgp_path_suppressed(pi))
// 		return false;

// 	return is_route_injectable_into_evpn_non_supp(pi);
// }

// /*
//  * Compare Route Targets.
//  */
// int bgp_evpn_route_target_cmp(struct ecommunity *ecom1,
// 			      struct ecommunity *ecom2)
// {
// 	if (ecom1 && !ecom2)
// 		return -1;

// 	if (!ecom1 && ecom2)
// 		return 1;

// 	if (!ecom1 && !ecom2)
// 		return 0;

// 	if (ecom1->str && !ecom2->str)
// 		return -1;

// 	if (!ecom1->str && ecom2->str)
// 		return 1;

// 	if (!ecom1->str && !ecom2->str)
// 		return 0;

// 	return strcmp(ecom1->str, ecom2->str);
// }

// /*
//  * Compare L3 Route Targets.
//  */
// static int evpn_vrf_route_target_cmp(struct vrf_route_target *rt1,
// 				     struct vrf_route_target *rt2)
// {
// 	return bgp_evpn_route_target_cmp(rt1->ecom, rt2->ecom);
// }

// void bgp_evpn_xxport_delete_ecomm(void *val)
// {
// 	struct ecommunity *ecomm = val;
// 	ecommunity_free(&ecomm);
// }

// /*
//  * Delete l3 Route Target.
//  */
// static void evpn_vrf_rt_del(void *val)
// {
// 	struct vrf_route_target *l3rt = val;

// 	ecommunity_free(&l3rt->ecom);

// 	XFREE(MTYPE_VRF_ROUTE_TARGET, l3rt);
// }

// /*
//  * Allocate a new l3 Route Target.
//  */
// static struct vrf_route_target *evpn_vrf_rt_new(struct ecommunity *ecom)
// {
// 	struct vrf_route_target *l3rt;

// 	l3rt = XCALLOC(MTYPE_VRF_ROUTE_TARGET, sizeof(struct vrf_route_target));

// 	l3rt->ecom = ecom;

// 	return l3rt;
// }

// /*
//  * Mask off global-admin field of specified extended community (RT),
//  * just retain the local-admin field.
//  */
// static inline void mask_ecom_global_admin(struct ecommunity_val *dst,
// 					  const struct ecommunity_val *src)
// {
// 	uint8_t type;

// 	type = src->val[0];
// 	dst->val[0] = 0;
// 	if (type == ECOMMUNITY_ENCODE_AS) {
// 		dst->val[2] = dst->val[3] = 0;
// 	} else if (type == ECOMMUNITY_ENCODE_AS4
// 		   || type == ECOMMUNITY_ENCODE_IP) {
// 		dst->val[2] = dst->val[3] = 0;
// 		dst->val[4] = dst->val[5] = 0;
// 	}
// }

// /*
//  * Converts the RT to Ecommunity Value and adjusts masking based
//  * on flags set for RT.
//  */
// static void vrf_rt2ecom_val(struct ecommunity_val *to_eval,
// 			    const struct vrf_route_target *l3rt, int iter)
// {
// 	const struct ecommunity_val *eval;

// 	eval = (const struct ecommunity_val *)(l3rt->ecom->val +
// 					       (iter * ECOMMUNITY_SIZE));
// 	/* If using "automatic" or "wildcard *" RT,
// 	 * we only care about the local-admin sub-field.
// 	 * This is to facilitate using L3VNI(VRF-VNI)
// 	 * as the RT for EBGP peering too and simplify
// 	 * configurations by allowing any ASN via '*'.
// 	 */
// 	memcpy(to_eval, eval, ECOMMUNITY_SIZE);

// 	if (CHECK_FLAG(l3rt->flags, BGP_VRF_RT_AUTO) ||
// 	    CHECK_FLAG(l3rt->flags, BGP_VRF_RT_WILD))
// 		mask_ecom_global_admin(to_eval, eval);
// }

// /*
//  * Map one RT to specified VRF.
//  * bgp_vrf = BGP vrf instance
//  */
// static void map_vrf_to_rt(struct bgp *bgp_vrf, struct vrf_route_target *l3rt)
// {
// 	uint32_t i = 0;

// 	for (i = 0; i < l3rt->ecom->size; i++) {
// 		struct vrf_irt_node *irt = NULL;
// 		struct ecommunity_val eval_tmp;

// 		/* Adjust masking for value */
// 		vrf_rt2ecom_val(&eval_tmp, l3rt, i);

// 		irt = lookup_vrf_import_rt(&eval_tmp);

// 		if (irt && is_vrf_present_in_irt_vrfs(irt->vrfs, bgp_vrf))
// 			return; /* Already mapped. */

// 		if (!irt)
// 			irt = vrf_import_rt_new(&eval_tmp);

// 		/* Add VRF to the list for this RT. */
// 		listnode_add(irt->vrfs, bgp_vrf);
// 	}
// }

// /*
//  * Unmap specified VRF from specified RT. If there are no other
//  * VRFs for this RT, then the RT hash is deleted.
//  * bgp_vrf: BGP VRF specific instance
//  */
// static void unmap_vrf_from_rt(struct bgp *bgp_vrf,
// 			      struct vrf_route_target *l3rt)
// {
// 	uint32_t i;

// 	for (i = 0; i < l3rt->ecom->size; i++) {
// 		struct vrf_irt_node *irt;
// 		struct ecommunity_val eval_tmp;

// 		/* Adjust masking for value */
// 		vrf_rt2ecom_val(&eval_tmp, l3rt, i);

// 		irt = lookup_vrf_import_rt(&eval_tmp);

// 		if (!irt)
// 			return; /* Not mapped */

// 		/* Delete VRF from list for this RT. */
// 		listnode_delete(irt->vrfs, bgp_vrf);

// 		if (!listnode_head(irt->vrfs))
// 			vrf_import_rt_free(irt);
// 	}
// }

// /*
//  * Map one RT to specified VNI.
//  */
// static void map_vni_to_rt(struct bgp *bgp, struct bgpevpn *vpn,
// 			  struct ecommunity_val *eval)
// {
// 	struct irt_node *irt;
// 	struct ecommunity_val eval_tmp;

// 	/* If using "automatic" RT, we only care about the local-admin
// 	 * sub-field.
// 	 * This is to facilitate using VNI as the RT for EBGP peering too.
// 	 */
// 	memcpy(&eval_tmp, eval, ECOMMUNITY_SIZE);
// 	if (!is_import_rt_configured(vpn))
// 		mask_ecom_global_admin(&eval_tmp, eval);

// 	irt = lookup_import_rt(bgp, &eval_tmp);
// 	if (irt)
// 		if (is_vni_present_in_irt_vnis(irt->vnis, vpn))
// 			/* Already mapped. */
// 			return;

// 	if (!irt)
// 		irt = import_rt_new(bgp, &eval_tmp);

// 	/* Add VNI to the hash list for this RT. */
// 	listnode_add(irt->vnis, vpn);
// }

// /*
//  * Unmap specified VNI from specified RT. If there are no other
//  * VNIs for this RT, then the RT hash is deleted.
//  */
// static void unmap_vni_from_rt(struct bgp *bgp, struct bgpevpn *vpn,
// 			      struct irt_node *irt)
// {
// 	/* Delete VNI from hash list for this RT. */
// 	listnode_delete(irt->vnis, vpn);
// 	if (!listnode_head(irt->vnis)) {
// 		import_rt_free(bgp, irt);
// 	}
// }

// static void bgp_evpn_get_rmac_nexthop(struct bgpevpn *vpn,
// 				      const struct prefix_evpn *p,
// 				      struct attr *attr, uint8_t flags)
// {
// 	struct bgp *bgp_vrf = vpn->bgp_vrf;

// 	memset(&attr->rmac, 0, sizeof(struct ethaddr));
// 	if (!bgp_vrf)
// 		return;

// 	if (p->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
// 		return;

// 	/* Copy sys (pip) RMAC and PIP IP as nexthop
// 	 * in case of route is self MAC-IP,
// 	 * advertise-pip and advertise-svi-ip features
// 	 * are enabled.
// 	 * Otherwise, for all host MAC-IP route's
// 	 * copy anycast RMAC.
// 	 */
// 	if (CHECK_FLAG(flags, BGP_EVPN_MACIP_TYPE_SVI_IP)
// 	    && bgp_vrf->evpn_info->advertise_pip &&
// 	    bgp_vrf->evpn_info->is_anycast_mac) {
// 		/* copy sys rmac */
// 		memcpy(&attr->rmac, &bgp_vrf->evpn_info->pip_rmac,
// 		       ETH_ALEN);
// 		attr->nexthop = bgp_vrf->evpn_info->pip_ip;
// 		attr->mp_nexthop_global_in =
// 			bgp_vrf->evpn_info->pip_ip;
// 	} else
// 		memcpy(&attr->rmac, &bgp_vrf->rmac, ETH_ALEN);
// }

// /*
//  * Create RT extended community automatically from passed information:
//  * of the form AS:VNI.
//  * NOTE: We use only the lower 16 bits of the AS. This is sufficient as
//  * the need is to get a RT value that will be unique across different
//  * VNIs but the same across routers (in the same AS) for a particular
//  * VNI.
//  */
// static void form_auto_rt(struct bgp *bgp, vni_t vni, struct list *rtl,
// 			 bool is_l3)
// {
// 	struct ecommunity_val eval;
// 	struct ecommunity *ecomadd;
// 	struct ecommunity *ecom;
// 	struct vrf_route_target *l3rt;
// 	struct vrf_route_target *newrt;
// 	bool ecom_found = false;
// 	struct listnode *node;

// 	if (bgp->advertise_autort_rfc8365)
// 		SET_FLAG(vni, EVPN_AUTORT_VXLAN);
// 	encode_route_target_as((bgp->as & 0xFFFF), vni, &eval, true);

// 	ecomadd = ecommunity_new();
// 	ecommunity_add_val(ecomadd, &eval, false, false);

// 	if (is_l3) {
// 		for (ALL_LIST_ELEMENTS_RO(rtl, node, l3rt))
// 			if (ecommunity_cmp(ecomadd, l3rt->ecom)) {
// 				ecom_found = true;
// 				break;
// 			}
// 	} else {
// 		for (ALL_LIST_ELEMENTS_RO(rtl, node, ecom))
// 			if (ecommunity_cmp(ecomadd, ecom)) {
// 				ecom_found = true;
// 				break;
// 			}
// 	}

// 	if (!ecom_found) {
// 		if (is_l3) {
// 			newrt = evpn_vrf_rt_new(ecomadd);
// 			/* Label it as autoderived */
// 			SET_FLAG(newrt->flags, BGP_VRF_RT_AUTO);
// 			listnode_add_sort(rtl, newrt);
// 		} else
// 			listnode_add_sort(rtl, ecomadd);
// 	} else
// 		ecommunity_free(&ecomadd);
// }

// /*
//  * Derive RD and RT for a VNI automatically. Invoked at the time of
//  * creation of a VNI.
//  */
// static void derive_rd_rt_for_vni(struct bgp *bgp, struct bgpevpn *vpn)
// {
// 	bgp_evpn_derive_auto_rd(bgp, vpn);
// 	bgp_evpn_derive_auto_rt_import(bgp, vpn);
// 	bgp_evpn_derive_auto_rt_export(bgp, vpn);
// }

// /*
//  * Convert nexthop (remote VTEP IP) into an IPv6 address.
//  */
// static void evpn_convert_nexthop_to_ipv6(struct attr *attr)
// {
// 	if (BGP_ATTR_NEXTHOP_AFI_IP6(attr))
// 		return;
// 	ipv4_to_ipv4_mapped_ipv6(&attr->mp_nexthop_global, attr->nexthop);
// 	attr->mp_nexthop_len = IPV6_MAX_BYTELEN;
// }

// /*
//  * Wrapper for node get in global table.
//  */
// struct bgp_dest *bgp_evpn_global_node_get(struct bgp_table *table, afi_t afi,
// 					  safi_t safi,
// 					  const struct prefix_evpn *evp,
// 					  struct prefix_rd *prd,
// 					  const struct bgp_path_info *local_pi)
// {
// 	struct prefix_evpn global_p;

// 	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE) {
// 		/* prefix in the global table doesn't include the VTEP-IP so
// 		 * we need to create a different copy of the prefix
// 		 */
// 		evpn_type1_prefix_global_copy(&global_p, evp);
// 		evp = &global_p;
// 	} else if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE &&
// 		   local_pi) {
// 		/*
// 		 * prefix in the global table needs MAC/IP, ensure they are
// 		 * present, using one's from local table's path_info.
// 		 */
// 		if (is_evpn_prefix_ipaddr_none(evp)) {
// 			/* VNI MAC -> Global */
// 			evpn_type2_prefix_global_copy(
// 				&global_p, evp, NULL /* mac */,
// 				evpn_type2_path_info_get_ip(local_pi));
// 		} else {
// 			/* VNI IP -> Global */
// 			evpn_type2_prefix_global_copy(
// 				&global_p, evp,
// 				evpn_type2_path_info_get_mac(local_pi),
// 				NULL /* ip */);
// 		}

// 		evp = &global_p;
// 	}
// 	return bgp_afi_node_get(table, afi, safi, (struct prefix *)evp, prd);
// }

// /*
//  * Wrapper for node lookup in global table.
//  */
// struct bgp_dest *bgp_evpn_global_node_lookup(
// 	struct bgp_table *table, safi_t safi, const struct prefix_evpn *evp,
// 	struct prefix_rd *prd, const struct bgp_path_info *local_pi)
// {
// 	struct prefix_evpn global_p;

// 	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE) {
// 		/* prefix in the global table doesn't include the VTEP-IP so
// 		 * we need to create a different copy of the prefix
// 		 */
// 		evpn_type1_prefix_global_copy(&global_p, evp);
// 		evp = &global_p;
// 	} else if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE &&
// 		   local_pi) {
// 		/*
// 		 * prefix in the global table needs MAC/IP, ensure they are
// 		 * present, using one's from local table's path_info.
// 		 */
// 		if (is_evpn_prefix_ipaddr_none(evp)) {
// 			/* VNI MAC -> Global */
// 			evpn_type2_prefix_global_copy(
// 				&global_p, evp, NULL /* mac */,
// 				evpn_type2_path_info_get_ip(local_pi));
// 		} else {
// 			/* VNI IP -> Global */
// 			evpn_type2_prefix_global_copy(
// 				&global_p, evp,
// 				evpn_type2_path_info_get_mac(local_pi),
// 				NULL /* ip */);
// 		}

// 		evp = &global_p;
// 	}
// 	return bgp_safi_node_lookup(table, safi, (struct prefix *)evp, prd);
// }

// /*
//  * Wrapper for node get in VNI IP table.
//  */
// struct bgp_dest *bgp_evpn_vni_ip_node_get(struct bgp_table *const table,
// 					  const struct prefix_evpn *evp,
// 					  const struct bgp_path_info *parent_pi)
// {
// 	struct prefix_evpn vni_p;

// 	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE && parent_pi) {
// 		/* prefix in the global table doesn't include the VTEP-IP so
// 		 * we need to create a different copy for the VNI
// 		 */
// 		evpn_type1_prefix_vni_ip_copy(&vni_p, evp,
// 					      parent_pi->attr->nexthop);
// 		evp = &vni_p;
// 	} else if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
// 		/* Only MAC-IP should go into this table, not mac-only */
// 		assert(is_evpn_prefix_ipaddr_none(evp) == false);

// 		/*
// 		 * prefix in the vni IP table doesn't include MAC so
// 		 * we need to create a different copy of the prefix.
// 		 */
// 		evpn_type2_prefix_vni_ip_copy(&vni_p, evp);
// 		evp = &vni_p;
// 	}
// 	return bgp_node_get(table, (struct prefix *)evp);
// }

// /*
//  * Wrapper for node lookup in VNI IP table.
//  */
// struct bgp_dest *
// bgp_evpn_vni_ip_node_lookup(const struct bgp_table *const table,
// 			    const struct prefix_evpn *evp,
// 			    const struct bgp_path_info *parent_pi)
// {
// 	struct prefix_evpn vni_p;

// 	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE && parent_pi) {
// 		/* prefix in the global table doesn't include the VTEP-IP so
// 		 * we need to create a different copy for the VNI
// 		 */
// 		evpn_type1_prefix_vni_ip_copy(&vni_p, evp,
// 					      parent_pi->attr->nexthop);
// 		evp = &vni_p;
// 	} else if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
// 		/* Only MAC-IP should go into this table, not mac-only */
// 		assert(is_evpn_prefix_ipaddr_none(evp) == false);

// 		/*
// 		 * prefix in the vni IP table doesn't include MAC so
// 		 * we need to create a different copy of the prefix.
// 		 */
// 		evpn_type2_prefix_vni_ip_copy(&vni_p, evp);
// 		evp = &vni_p;
// 	}
// 	return bgp_node_lookup(table, (struct prefix *)evp);
// }

// /*
//  * Wrapper for node get in VNI MAC table.
//  */
// struct bgp_dest *
// bgp_evpn_vni_mac_node_get(struct bgp_table *const table,
// 			  const struct prefix_evpn *evp,
// 			  const struct bgp_path_info *parent_pi)
// {
// 	struct prefix_evpn vni_p;

// 	/* Only type-2 should ever go into this table */
// 	assert(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE);

// 	/*
// 	 * prefix in the vni MAC table doesn't include IP so
// 	 * we need to create a different copy of the prefix.
// 	 */
// 	evpn_type2_prefix_vni_mac_copy(&vni_p, evp);
// 	evp = &vni_p;
// 	return bgp_node_get(table, (struct prefix *)evp);
// }

// /*
//  * Wrapper for node lookup in VNI MAC table.
//  */
// struct bgp_dest *
// bgp_evpn_vni_mac_node_lookup(const struct bgp_table *const table,
// 			     const struct prefix_evpn *evp,
// 			     const struct bgp_path_info *parent_pi)
// {
// 	struct prefix_evpn vni_p;

// 	/* Only type-2 should ever go into this table */
// 	assert(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE);

// 	/*
// 	 * prefix in the vni MAC table doesn't include IP so
// 	 * we need to create a different copy of the prefix.
// 	 */
// 	evpn_type2_prefix_vni_mac_copy(&vni_p, evp);
// 	evp = &vni_p;
// 	return bgp_node_lookup(table, (struct prefix *)evp);
// }

// /*
//  * Wrapper for node get in both VNI tables.
//  */
// struct bgp_dest *bgp_evpn_vni_node_get(struct bgpevpn *vpn,
// 				       const struct prefix_evpn *p,
// 				       const struct bgp_path_info *parent_pi)
// {
// 	if ((p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) &&
// 	    (is_evpn_prefix_ipaddr_none(p) == true))
// 		return bgp_evpn_vni_mac_node_get(vpn->mac_table, p, parent_pi);

// 	return bgp_evpn_vni_ip_node_get(vpn->ip_table, p, parent_pi);
// }

// /*
//  * Wrapper for node lookup in both VNI tables.
//  */
// struct bgp_dest *bgp_evpn_vni_node_lookup(const struct bgpevpn *vpn,
// 					  const struct prefix_evpn *p,
// 					  const struct bgp_path_info *parent_pi)
// {
// 	if ((p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) &&
// 	    (is_evpn_prefix_ipaddr_none(p) == true))
// 		return bgp_evpn_vni_mac_node_lookup(vpn->mac_table, p,
// 						    parent_pi);

// 	return bgp_evpn_vni_ip_node_lookup(vpn->ip_table, p, parent_pi);
// }

// /*
//  * Add (update) or delete MACIP from zebra.
//  */
// static enum zclient_send_status bgp_zebra_send_remote_macip(
// 	struct bgp *bgp, struct bgpevpn *vpn, const struct prefix_evpn *p,
// 	const struct ethaddr *mac, struct in_addr remote_vtep_ip, int add,
// 	uint8_t flags, uint32_t seq, esi_t *esi)
// {
// 	struct stream *s;
// 	uint16_t ipa_len;
// 	static struct in_addr zero_remote_vtep_ip;
// 	bool esi_valid;

// 	/* Check socket. */
// 	if (!bgp_zclient || bgp_zclient->sock < 0) {
// 		if (BGP_DEBUG(zebra, ZEBRA))
// 			zlog_debug("%s: No zclient or zclient->sock exists",
// 				   __func__);
// 		return ZCLIENT_SEND_SUCCESS;
// 	}

// 	/* Don't try to register if Zebra doesn't know of this instance. */
// 	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp)) {
// 		if (BGP_DEBUG(zebra, ZEBRA))
// 			zlog_debug(
// 				"%s: No zebra instance to talk to, not installing remote macip",
// 				__func__);
// 		return ZCLIENT_SEND_SUCCESS;
// 	}

// 	if (!esi)
// 		esi = zero_esi;
// 	s = bgp_zclient->obuf;
// 	stream_reset(s);

// 	zclient_create_header(
// 		s, add ? ZEBRA_REMOTE_MACIP_ADD : ZEBRA_REMOTE_MACIP_DEL,
// 		bgp->vrf_id);
// 	stream_putl(s, vpn ? vpn->vni : 0);

// 	if (mac) /* Mac Addr */
// 		stream_put(s, &mac->octet, ETH_ALEN);
// 	else
// 		stream_put(s, &p->prefix.macip_addr.mac.octet, ETH_ALEN);

// 	/* IP address length and IP address, if any. */
// 	if (is_evpn_prefix_ipaddr_none(p))
// 		stream_putw(s, 0);
// 	else {
// 		ipa_len = is_evpn_prefix_ipaddr_v4(p) ? IPV4_MAX_BYTELEN
// 						      : IPV6_MAX_BYTELEN;
// 		stream_putw(s, ipa_len);
// 		stream_put(s, &p->prefix.macip_addr.ip.ip.addr, ipa_len);
// 	}
// 	/* If the ESI is valid that becomes the nexthop; tape out the
// 	 * VTEP-IP for that case
// 	 */
// 	if (bgp_evpn_is_esi_valid(esi)) {
// 		esi_valid = true;
// 		stream_put_in_addr(s, &zero_remote_vtep_ip);
// 	} else {
// 		esi_valid = false;
// 		stream_put_in_addr(s, &remote_vtep_ip);
// 	}

// 	/* TX flags - MAC sticky status and/or gateway mac */
// 	/* Also TX the sequence number of the best route. */
// 	if (add) {
// 		stream_putc(s, flags);
// 		stream_putl(s, seq);
// 		stream_put(s, esi, sizeof(esi_t));
// 	}

// 	stream_putw_at(s, 0, stream_get_endp(s));

// 	if (bgp_debug_zebra(NULL)) {
// 		char esi_buf[ESI_STR_LEN];

// 		if (esi_valid)
// 			esi_to_str(esi, esi_buf, sizeof(esi_buf));
// 		else
// 			snprintf(esi_buf, sizeof(esi_buf), "-");
// 		zlog_debug(
// 			"Tx %s MACIP, VNI %u MAC %pEA IP %pIA flags 0x%x seq %u remote VTEP %pI4 esi %s",
// 			add ? "ADD" : "DEL", (vpn ? vpn->vni : 0),
// 			(mac ? mac : &p->prefix.macip_addr.mac),
// 			&p->prefix.macip_addr.ip, flags, seq, &remote_vtep_ip,
// 			esi_buf);
// 	}

// 	frrtrace(5, frr_bgp, evpn_mac_ip_zsend, add, vpn, p, remote_vtep_ip,
// 		 esi);

// 	return zclient_send_message(bgp_zclient);
// }

// /*
//  * Add (update) or delete remote VTEP from zebra.
//  */
// static enum zclient_send_status
// bgp_zebra_send_remote_vtep(struct bgp *bgp, struct bgpevpn *vpn,
// 			   const struct prefix_evpn *p, int flood_control,
// 			   int add)
// {
// 	struct stream *s;

// 	/* Check socket. */
// 	if (!bgp_zclient || bgp_zclient->sock < 0) {
// 		if (BGP_DEBUG(zebra, ZEBRA))
// 			zlog_debug("%s: No zclient or zclient->sock exists",
// 				   __func__);
// 		return ZCLIENT_SEND_SUCCESS;
// 	}

// 	/* Don't try to register if Zebra doesn't know of this instance. */
// 	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp)) {
// 		if (BGP_DEBUG(zebra, ZEBRA))
// 			zlog_debug(
// 				"%s: No zebra instance to talk to, not installing remote vtep",
// 				__func__);
// 		return ZCLIENT_SEND_SUCCESS;
// 	}

// 	s = bgp_zclient->obuf;
// 	stream_reset(s);

// 	zclient_create_header(
// 		s, add ? ZEBRA_REMOTE_VTEP_ADD : ZEBRA_REMOTE_VTEP_DEL,
// 		bgp->vrf_id);
// 	stream_putl(s, vpn ? vpn->vni : 0);
// 	if (is_evpn_prefix_ipaddr_v4(p))
// 		stream_put_in_addr(s, &p->prefix.imet_addr.ip.ipaddr_v4);
// 	else if (is_evpn_prefix_ipaddr_v6(p)) {
// 		flog_err(
// 			EC_BGP_VTEP_INVALID,
// 			"Bad remote IP when trying to %s remote VTEP for VNI %u",
// 			add ? "ADD" : "DEL", (vpn ? vpn->vni : 0));
// 		return ZCLIENT_SEND_FAILURE;
// 	}
// 	stream_putl(s, flood_control);

// 	stream_putw_at(s, 0, stream_get_endp(s));

// 	if (bgp_debug_zebra(NULL))
// 		zlog_debug("Tx %s Remote VTEP, VNI %u (flood control %d) remote VTEP %pI4",
// 			   add ? "ADD" : "DEL", (vpn ? vpn->vni : 0), flood_control,
// 			   &p->prefix.imet_addr.ip.ipaddr_v4);

// 	frrtrace(3, frr_bgp, evpn_bum_vtep_zsend, add, vpn, p);

// 	return zclient_send_message(bgp_zclient);
// }

// /*
//  * Build extended communities for EVPN prefix route.
//  */
// static void build_evpn_type5_route_extcomm(struct bgp *bgp_vrf,
// 					   struct attr *attr)
// {
// 	struct ecommunity ecom_encap;
// 	struct ecommunity_val eval;
// 	struct ecommunity_val eval_rmac;
// 	bgp_encap_types tnl_type;
// 	struct listnode *node, *nnode;
// 	struct vrf_route_target *l3rt;
// 	struct ecommunity *old_ecom;
// 	struct ecommunity *ecom;
// 	struct list *vrf_export_rtl = NULL;

// 	/* Encap */
// 	tnl_type = BGP_ENCAP_TYPE_VXLAN;
// 	memset(&ecom_encap, 0, sizeof(ecom_encap));
// 	encode_encap_extcomm(tnl_type, &eval);
// 	ecom_encap.size = 1;
// 	ecom_encap.unit_size = ECOMMUNITY_SIZE;
// 	ecom_encap.val = (uint8_t *)eval.val;

// 	/* Add Encap */
// 	if (bgp_attr_get_ecommunity(attr)) {
// 		old_ecom = bgp_attr_get_ecommunity(attr);
// 		ecom = ecommunity_merge(ecommunity_dup(old_ecom), &ecom_encap);
// 		if (!old_ecom->refcnt)
// 			ecommunity_free(&old_ecom);
// 	} else
// 		ecom = ecommunity_dup(&ecom_encap);
// 	bgp_attr_set_ecommunity(attr, ecom);
// 	attr->encap_tlvs->tunnel_type = tnl_type;

// 	/* Add the export RTs for L3VNI/VRF */
// 	vrf_export_rtl = bgp_vrf->vrf_export_rtl;
// 	for (ALL_LIST_ELEMENTS(vrf_export_rtl, node, nnode, l3rt))
// 		bgp_attr_set_ecommunity(
// 			attr, ecommunity_merge(bgp_attr_get_ecommunity(attr),
// 					       l3rt->ecom));

// 	/* add the router mac extended community */
// 	if (!is_zero_mac(&attr->rmac)) {
// 		encode_rmac_extcomm(&eval_rmac, &attr->rmac);
// 		ecommunity_add_val(bgp_attr_get_ecommunity(attr), &eval_rmac,
// 				   true, true);
// 	}
// }

// /*
//  * Build extended communities for EVPN route.
//  * This function is applicable for type-2 and type-3 routes. The layer-2 RT
//  * and ENCAP extended communities are applicable for all routes.
//  * The default gateway extended community and MAC mobility (sticky) extended
//  * community are added as needed based on passed settings - only for type-2
//  * routes. Likewise, the layer-3 RT and Router MAC extended communities are
//  * added, if present, based on passed settings - only for non-link-local
//  * type-2 routes.
//  */
// static void build_evpn_route_extcomm(struct bgpevpn *vpn, struct attr *attr,
// 				     int add_l3_ecomm,
// 				     struct ecommunity *macvrf_soo)
// {
// 	struct ecommunity ecom_encap;
// 	struct ecommunity ecom_sticky;
// 	struct ecommunity ecom_default_gw;
// 	struct ecommunity ecom_na;
// 	struct ecommunity_val eval;
// 	struct ecommunity_val eval_sticky;
// 	struct ecommunity_val eval_default_gw;
// 	struct ecommunity_val eval_rmac;
// 	struct ecommunity_val eval_na;
// 	bool proxy;

// 	bgp_encap_types tnl_type;
// 	struct listnode *node, *nnode;
// 	struct ecommunity *ecom;
// 	struct vrf_route_target *l3rt;
// 	uint32_t seqnum;
// 	struct list *vrf_export_rtl = NULL;

// 	/* Encap */
// 	tnl_type = BGP_ENCAP_TYPE_VXLAN;
// 	memset(&ecom_encap, 0, sizeof(ecom_encap));
// 	encode_encap_extcomm(tnl_type, &eval);
// 	ecom_encap.size = 1;
// 	ecom_encap.unit_size = ECOMMUNITY_SIZE;
// 	ecom_encap.val = (uint8_t *)eval.val;

// 	/* Add Encap */
// 	bgp_attr_set_ecommunity(attr, ecommunity_dup(&ecom_encap));
// 	attr->encap_tlvs->tunnel_type = tnl_type;

// 	/* Add the export RTs for L2VNI */
// 	for (ALL_LIST_ELEMENTS(vpn->export_rtl, node, nnode, ecom))
// 		bgp_attr_set_ecommunity(
// 			attr,
// 			ecommunity_merge(bgp_attr_get_ecommunity(attr), ecom));

// 	/* Add the export RTs for L3VNI if told to - caller determines
// 	 * when this should be done.
// 	 */
// 	if (add_l3_ecomm) {
// 		vrf_export_rtl = bgpevpn_get_vrf_export_rtl(vpn);
// 		if (vrf_export_rtl && !list_isempty(vrf_export_rtl)) {
// 			for (ALL_LIST_ELEMENTS(vrf_export_rtl, node, nnode,
// 					       l3rt))
// 				bgp_attr_set_ecommunity(
// 					attr,
// 					ecommunity_merge(
// 						bgp_attr_get_ecommunity(attr),
// 						l3rt->ecom));
// 		}
// 	}

// 	/* Add MAC mobility (sticky) if needed. */
// 	if (CHECK_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_STICKY)) {
// 		seqnum = 0;
// 		encode_mac_mobility_extcomm(1, seqnum, &eval_sticky);
// 		ecom_sticky.size = 1;
// 		ecom_sticky.unit_size = ECOMMUNITY_SIZE;
// 		ecom_sticky.val = (uint8_t *)eval_sticky.val;
// 		bgp_attr_set_ecommunity(
// 			attr, ecommunity_merge(bgp_attr_get_ecommunity(attr),
// 					       &ecom_sticky));
// 	}

// 	/* Add RMAC, if told to. */
// 	if (add_l3_ecomm) {
// 		encode_rmac_extcomm(&eval_rmac, &attr->rmac);
// 		ecommunity_add_val(bgp_attr_get_ecommunity(attr), &eval_rmac,
// 				   true, true);
// 	}

// 	/* Add default gateway, if needed. */
// 	if (CHECK_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_DEFAULT_GW)) {
// 		encode_default_gw_extcomm(&eval_default_gw);
// 		ecom_default_gw.size = 1;
// 		ecom_default_gw.unit_size = ECOMMUNITY_SIZE;
// 		ecom_default_gw.val = (uint8_t *)eval_default_gw.val;
// 		bgp_attr_set_ecommunity(
// 			attr, ecommunity_merge(bgp_attr_get_ecommunity(attr),
// 					       &ecom_default_gw));
// 	}

// 	proxy = !!(attr->es_flags & ATTR_ES_PROXY_ADVERT);
// 	if (CHECK_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_ROUTER) || proxy) {
// 		encode_na_flag_extcomm(&eval_na,
// 				       CHECK_FLAG(attr->evpn_flags,
// 						  ATTR_EVPN_FLAG_ROUTER),
// 				       proxy);
// 		ecom_na.size = 1;
// 		ecom_na.unit_size = ECOMMUNITY_SIZE;
// 		ecom_na.val = (uint8_t *)eval_na.val;
// 		bgp_attr_set_ecommunity(
// 			attr, ecommunity_merge(bgp_attr_get_ecommunity(attr),
// 					       &ecom_na));
// 	}

// 	/* Add MAC-VRF SoO, if configured */
// 	if (macvrf_soo)
// 		bgp_attr_set_ecommunity(
// 			attr, ecommunity_merge(attr->ecommunity, macvrf_soo));
// }

// /*
//  * Add MAC mobility extended community to attribute.
//  */
// static void add_mac_mobility_to_attr(uint32_t seq_num, struct attr *attr)
// {
// 	struct ecommunity ecom_tmp;
// 	struct ecommunity_val eval;
// 	uint8_t *ecom_val_ptr;
// 	uint32_t i;
// 	uint8_t *pnt;
// 	int type = 0;
// 	int sub_type = 0;
// 	struct ecommunity *ecomm = bgp_attr_get_ecommunity(attr);

// 	/* Build MM */
// 	encode_mac_mobility_extcomm(0, seq_num, &eval);

// 	/* Find current MM ecommunity */
// 	ecom_val_ptr = NULL;

// 	if (ecomm) {
// 		for (i = 0; i < ecomm->size; i++) {
// 			pnt = ecomm->val + (i * ecomm->unit_size);
// 			type = *pnt++;
// 			sub_type = *pnt++;

// 			if (type == ECOMMUNITY_ENCODE_EVPN
// 			    && sub_type
// 				       == ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY) {
// 				ecom_val_ptr =
// 					(ecomm->val + (i * ecomm->unit_size));
// 				break;
// 			}
// 		}
// 	}

// 	/* Update the existing MM ecommunity */
// 	if (ecom_val_ptr) {
// 		memcpy(ecom_val_ptr, eval.val, sizeof(char) * ecomm->unit_size);
// 	}
// 	/* Add MM to existing */
// 	else {
// 		memset(&ecom_tmp, 0, sizeof(ecom_tmp));
// 		ecom_tmp.size = 1;
// 		ecom_tmp.unit_size = ECOMMUNITY_SIZE;
// 		ecom_tmp.val = (uint8_t *)eval.val;

// 		if (ecomm)
// 			bgp_attr_set_ecommunity(
// 				attr, ecommunity_merge(ecomm, &ecom_tmp));
// 		else
// 			bgp_attr_set_ecommunity(attr,
// 						ecommunity_dup(&ecom_tmp));
// 	}
// }

// /* Install EVPN route into zebra. */
// enum zclient_send_status evpn_zebra_install(struct bgp *bgp, struct bgpevpn *vpn,
// 					    const struct prefix_evpn *p,
// 					    struct bgp_path_info *pi)
// {
// 	uint8_t flags;
// 	int flood_control = VXLAN_FLOOD_DISABLED;
// 	uint32_t seq;
// 	enum zclient_send_status ret = ZCLIENT_SEND_SUCCESS;

// 	if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
// 		flags = 0;

// 		if (pi->sub_type == BGP_ROUTE_IMPORTED) {
// 			if (CHECK_FLAG(pi->attr->evpn_flags,
// 				       ATTR_EVPN_FLAG_STICKY))
// 				SET_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY);
// 			if (CHECK_FLAG(pi->attr->evpn_flags,
// 				       ATTR_EVPN_FLAG_DEFAULT_GW))
// 				SET_FLAG(flags, ZEBRA_MACIP_TYPE_GW);
// 			if (is_evpn_prefix_ipaddr_v6(p) &&
// 			    CHECK_FLAG(pi->attr->evpn_flags,
// 				       ATTR_EVPN_FLAG_ROUTER))
// 				SET_FLAG(flags, ZEBRA_MACIP_TYPE_ROUTER_FLAG);

// 			seq = mac_mobility_seqnum(pi->attr);
// 			/* if local ES notify zebra that this is a sync path */
// 			if (bgp_evpn_attr_is_local_es(pi->attr)) {
// 				SET_FLAG(flags, ZEBRA_MACIP_TYPE_SYNC_PATH);
// 				if (bgp_evpn_attr_is_proxy(pi->attr))
// 					SET_FLAG(flags,
// 						ZEBRA_MACIP_TYPE_PROXY_ADVERT);
// 			}
// 		} else {
// 			if (!bgp_evpn_attr_is_sync(pi->attr))
// 				return 0;

// 			/* if a local path is being turned around and sent
// 			 * to zebra it is because it is a sync path on
// 			 * a local ES
// 			 */
// 			SET_FLAG(flags, ZEBRA_MACIP_TYPE_SYNC_PATH);
// 			/* supply the highest peer seq number to zebra
// 			 * for MM seq syncing
// 			 */
// 			seq = bgp_evpn_attr_get_sync_seq(pi->attr);
// 			/* if any of the paths from the peer have the ROUTER
// 			 * flag set install the local entry as a router entry
// 			 */
// 			if (is_evpn_prefix_ipaddr_v6(p) &&
// 			    CHECK_FLAG(pi->attr->es_flags, ATTR_ES_PEER_ROUTER))
// 				SET_FLAG(flags,
// 						ZEBRA_MACIP_TYPE_ROUTER_FLAG);

// 			if (!CHECK_FLAG(pi->attr->es_flags, ATTR_ES_PEER_ACTIVE))
// 				SET_FLAG(flags,
// 						ZEBRA_MACIP_TYPE_PROXY_ADVERT);
// 		}

// 		ret = bgp_zebra_send_remote_macip(
// 			bgp, vpn, p,
// 			(is_evpn_prefix_ipaddr_none(p)
// 				 ? NULL /* MAC update */
// 				 : evpn_type2_path_info_get_mac(
// 					   pi) /* MAC-IP update */),
// 			pi->attr->nexthop, 1, flags, seq,
// 			bgp_evpn_attr_get_esi(pi->attr));
// 	} else if (p->prefix.route_type == BGP_EVPN_AD_ROUTE) {
// 		ret = bgp_evpn_remote_es_evi_add(bgp, vpn, p);
// 	} else {
// 		switch (bgp_attr_get_pmsi_tnl_type(pi->attr)) {
// 		case PMSI_TNLTYPE_INGR_REPL:
// 			flood_control = VXLAN_FLOOD_HEAD_END_REPL;
// 			break;

// 		case PMSI_TNLTYPE_PIM_SM:
// 			flood_control = VXLAN_FLOOD_PIM_SM;
// 			break;

// 		case PMSI_TNLTYPE_NO_INFO:
// 		case PMSI_TNLTYPE_RSVP_TE_P2MP:
// 		case PMSI_TNLTYPE_MLDP_P2MP:
// 		case PMSI_TNLTYPE_PIM_SSM:
// 		case PMSI_TNLTYPE_PIM_BIDIR:
// 		case PMSI_TNLTYPE_MLDP_MP2MP:
// 			flood_control = VXLAN_FLOOD_DISABLED;
// 			break;
// 		}

// 		ret = bgp_zebra_send_remote_vtep(bgp, vpn, p, flood_control, 1);
// 	}

// 	return ret;
// }

// /* Uninstall EVPN route from zebra. */
// enum zclient_send_status evpn_zebra_uninstall(struct bgp *bgp,
// 					      struct bgpevpn *vpn,
// 					      const struct prefix_evpn *p,
// 					      struct bgp_path_info *pi,
// 					      bool is_sync)
// {
// 	enum zclient_send_status ret = ZCLIENT_SEND_SUCCESS;

// 	if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
// 		ret = bgp_zebra_send_remote_macip(
// 			bgp, vpn, p,
// 			(is_evpn_prefix_ipaddr_none(p)
// 				 ? NULL /* MAC update */
// 				 : evpn_type2_path_info_get_mac(
// 					   pi) /* MAC-IP update */),
// 			(is_sync ? zero_vtep_ip : pi->attr->nexthop), 0, 0, 0,
// 			NULL);
// 	else if (p->prefix.route_type == BGP_EVPN_AD_ROUTE)
// 		ret = bgp_evpn_remote_es_evi_del(bgp, vpn, p);
// 	else
// 		ret = bgp_zebra_send_remote_vtep(bgp, vpn, p,
// 						 VXLAN_FLOOD_DISABLED, 0);

// 	return ret;
// }

// /*
//  * Due to MAC mobility, the prior "local" best route has been supplanted
//  * by a "remote" best route. The prior route has to be deleted and withdrawn
//  * from peers.
//  */
// static void evpn_delete_old_local_route(struct bgp *bgp, struct bgpevpn *vpn,
// 					struct bgp_dest *dest,
// 					struct bgp_path_info *old_local,
// 					struct bgp_path_info *new_select)
// {
// 	struct bgp_dest *global_dest;
// 	struct bgp_path_info *pi;
// 	afi_t afi = AFI_L2VPN;
// 	safi_t safi = SAFI_EVPN;

// 	if (BGP_DEBUG(evpn_mh, EVPN_MH_RT)) {
// 		char esi_buf[ESI_STR_LEN];
// 		char esi_buf2[ESI_STR_LEN];
// 		struct prefix_evpn *evp =
// 			(struct prefix_evpn *)bgp_dest_get_prefix(dest);

// 		zlog_debug("local path deleted %pFX es %s; new-path-es %s", evp,
// 			   esi_to_str(&old_local->attr->esi, esi_buf,
// 				      sizeof(esi_buf)),
// 			   new_select ? esi_to_str(&new_select->attr->esi,
// 						   esi_buf2, sizeof(esi_buf2))
// 				      : "");
// 	}

// 	/* Locate route node in the global EVPN routing table. Note that
// 	 * this table is a 2-level tree (RD-level + Prefix-level) similar to
// 	 * L3VPN routes.
// 	 */
// 	global_dest = bgp_evpn_global_node_lookup(
// 		bgp->rib[afi][safi], safi,
// 		(const struct prefix_evpn *)bgp_dest_get_prefix(dest),
// 		&vpn->prd, old_local);
// 	if (global_dest) {
// 		/* Delete route entry in the global EVPN table. */
// 		pi = delete_evpn_route_entry(bgp, afi, safi, global_dest, 0);

// 		/* Schedule for processing - withdraws to peers happen from
// 		 * this table.
// 		 */
// 		if (pi)
// 			bgp_process(bgp, global_dest, pi, afi, safi);
// 		bgp_dest_unlock_node(global_dest);
// 	}

// 	/* Delete route entry in the VNI route table, caller to remove. */
// 	bgp_path_info_mark_for_delete(dest, old_local);
// }

// /*
//  * Calculate the best path for an EVPN route. Install/update best path in zebra,
//  * if appropriate.
//  * Note: vpn is NULL for local EAD-ES routes.
//  */
// int evpn_route_select_install(struct bgp *bgp, struct bgpevpn *vpn,
// 			      struct bgp_dest *dest, struct bgp_path_info *pi)
// {
// 	struct bgp_path_info *old_select, *new_select, *first;
// 	struct bgp_path_info_pair old_and_new;
// 	afi_t afi = AFI_L2VPN;
// 	safi_t safi = SAFI_EVPN;
// 	int ret = 0;

// 	first = bgp_dest_get_bgp_path_info(dest);
// 	SET_FLAG(pi->flags, BGP_PATH_UNSORTED);
// 	if (pi != first) {
// 		if (pi->next)
// 			pi->next->prev = pi->prev;
// 		if (pi->prev)
// 			pi->prev->next = pi->next;

// 		if (first)
// 			first->prev = pi;
// 		pi->next = first;
// 		pi->prev = NULL;
// 		bgp_dest_set_bgp_path_info(dest, pi);
// 	}

// 	/* Compute the best path. */
// 	bgp_best_selection(bgp, dest, &bgp->maxpaths[afi][safi], &old_and_new,
// 			   afi, safi);
// 	old_select = old_and_new.old;
// 	new_select = old_and_new.new;

// 	/* If the best path hasn't changed - see if there is still something to
// 	 * update to zebra RIB.
// 	 * Remote routes and SYNC route (i.e. local routes with
// 	 * SYNCED_FROM_PEER flag) need to updated to zebra on any attr
// 	 * change.
// 	 */
// 	if (old_select && old_select == new_select
// 	    && old_select->type == ZEBRA_ROUTE_BGP
// 	    && (old_select->sub_type == BGP_ROUTE_IMPORTED ||
// 			bgp_evpn_attr_is_sync(old_select->attr))
// 	    && !CHECK_FLAG(dest->flags, BGP_NODE_USER_CLEAR)
// 	    && !CHECK_FLAG(old_select->flags, BGP_PATH_ATTR_CHANGED)
// 	    && !bgp_addpath_is_addpath_used(&bgp->tx_addpath, afi, safi)) {
// 		if (bgp_zebra_has_route_changed(old_select)) {
// 			if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS))
// 				ret = evpn_zebra_install(bgp, vpn,
// 							 (const struct prefix_evpn
// 								  *)
// 								 bgp_dest_get_prefix(
// 									 dest),
// 							 old_select);
// 			else
// 				bgp_zebra_route_install(dest, old_select, bgp,
// 							true, vpn, false);
// 		}

// 		UNSET_FLAG(old_select->flags, BGP_PATH_MULTIPATH_CHG);
// 		UNSET_FLAG(old_select->flags, BGP_PATH_LINK_BW_CHG);
// 		bgp_zebra_clear_route_change_flags(dest);
// 		return ret;
// 	}

// 	/* If the user did a "clear" this flag will be set */
// 	UNSET_FLAG(dest->flags, BGP_NODE_USER_CLEAR);

// 	/* bestpath has changed; update relevant fields and install or uninstall
// 	 * into the zebra RIB.
// 	 */
// 	if (old_select || new_select)
// 		bgp_bump_version(dest);

// 	if (old_select)
// 		bgp_path_info_unset_flag(dest, old_select, BGP_PATH_SELECTED);
// 	if (new_select) {
// 		bgp_path_info_set_flag(dest, new_select, BGP_PATH_SELECTED);
// 		bgp_path_info_unset_flag(dest, new_select,
// 					 BGP_PATH_ATTR_CHANGED);
// 		UNSET_FLAG(new_select->flags, BGP_PATH_MULTIPATH_CHG);
// 		UNSET_FLAG(new_select->flags, BGP_PATH_LINK_BW_CHG);
// 	}

// 	/* a local entry with the SYNC flag also results in a MAC-IP update
// 	 * to zebra
// 	 */
// 	if (new_select && new_select->type == ZEBRA_ROUTE_BGP
// 	    && (new_select->sub_type == BGP_ROUTE_IMPORTED ||
// 			bgp_evpn_attr_is_sync(new_select->attr))) {
// 		if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS))
// 			ret = evpn_zebra_install(bgp, vpn,
// 						 (const struct prefix_evpn *)
// 							 bgp_dest_get_prefix(
// 								 dest),
// 						 new_select);
// 		else
// 			bgp_zebra_route_install(dest, new_select, bgp, true,
// 						vpn, false);

// 		/* If an old best existed and it was a "local" route, the only
// 		 * reason
// 		 * it would be supplanted is due to MAC mobility procedures. So,
// 		 * we
// 		 * need to do an implicit delete and withdraw that route from
// 		 * peers.
// 		 */
// 		if (new_select->sub_type == BGP_ROUTE_IMPORTED &&
// 				old_select && old_select->peer == bgp->peer_self
// 				&& old_select->type == ZEBRA_ROUTE_BGP
// 				&& old_select->sub_type == BGP_ROUTE_STATIC
// 				&& vpn)
// 			evpn_delete_old_local_route(bgp, vpn, dest,
// 					old_select, new_select);
// 	} else {
// 		if (old_select && old_select->type == ZEBRA_ROUTE_BGP &&
// 		    old_select->sub_type == BGP_ROUTE_IMPORTED) {
// 			if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS) ||
// 			    CHECK_FLAG(bgp->flags, BGP_FLAG_VNI_DOWN))
// 				ret = evpn_zebra_uninstall(bgp, vpn,
// 							   (const struct prefix_evpn
// 								    *)
// 								   bgp_dest_get_prefix(
// 									   dest),
// 							   old_select, false);
// 			else
// 				bgp_zebra_route_install(dest, old_select, bgp,
// 							false, vpn, false);
// 		}
// 	}

// 	/* Clear any route change flags. */
// 	bgp_zebra_clear_route_change_flags(dest);

// 	/* Reap old select bgp_path_info, if it has been removed */
// 	if (old_select && CHECK_FLAG(old_select->flags, BGP_PATH_REMOVED))
// 		bgp_path_info_reap(dest, old_select);

// 	return ret;
// }

// static struct bgp_path_info *bgp_evpn_route_get_local_path(struct bgp *bgp, struct bgp_dest *dest,
// 							   uint32_t addpath_id)
// {
// 	struct bgp_path_info *pi = NULL;

// 	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
// 		if (bgp_evpn_is_path_local(bgp, pi) && pi->addpath_rx_id == addpath_id)
// 			return pi;
// 	}

// 	return NULL;
// }

// static int update_evpn_type5_route_entry(struct bgp *bgp_evpn, struct bgp *bgp_vrf, afi_t afi,
// 					 safi_t safi, struct bgp_dest *dest, struct attr *attr,
// 					 int *route_changed, struct bgp_path_info **entry,
// 					 uint32_t addpath_id)
// {
// 	struct attr *attr_new = NULL;
// 	struct bgp_path_info *pi = NULL;
// 	struct bgp_labels bgp_labels = {};
// 	struct bgp_path_info *local_pi = NULL;
// 	struct bgp_path_info *tmp_pi = NULL;
// 	struct aspath *new_aspath;
// 	struct attr static_attr = { 0 };

// 	*route_changed = 0;

// 	/* See if this is an update of an existing route, or a new add. */
// 	local_pi = bgp_evpn_route_get_local_path(bgp_evpn, dest, addpath_id);

// 	static_attr = *attr;

// 	/*
// 	 * create a new route entry if one doesn't exist.
// 	 * Otherwise see if route attr has changed
// 	 */
// 	if (!local_pi) {

// 		/* route has changed as this is the first entry */
// 		*route_changed = 1;

// 		/*
// 		 * if the asn values are different, copy the as of
// 		 * source vrf to the target entry
// 		 */
// 		if (bgp_vrf->as != bgp_evpn->as) {
// 			new_aspath = aspath_dup(static_attr.aspath);
// 			new_aspath = aspath_add_seq(new_aspath, bgp_vrf->as);
// 			static_attr.aspath = new_aspath;
// 		}

// 		/* Add (or update) attribute to hash. */
// 		attr_new = bgp_attr_intern(&static_attr);
// 		bgp_attr_flush(&static_attr);

// 		/* create the route info from attribute */
// 		pi = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0,
// 			       bgp_evpn->peer_self, attr_new, dest);
// 		SET_FLAG(pi->flags, BGP_PATH_VALID);
// 		if (local_pi)
// 			SET_FLAG(pi->flags, BGP_PATH_MULTIPATH);

// 		/* Type-5 routes advertise the L3-VNI */
// 		bgp_path_info_extra_get(pi);
// 		vni2label(bgp_vrf->l3vni, &bgp_labels.label[0]);
// 		bgp_labels.num_labels = 1;
// 		if (!bgp_path_info_labels_same(pi, &bgp_labels.label[0],
// 					       bgp_labels.num_labels)) {
// 			bgp_labels_unintern(&pi->extra->labels);
// 			pi->extra->labels = bgp_labels_intern(&bgp_labels);
// 		}

// 		/* handle addpath: use the original route's tx id as our rx id */
// 		pi->addpath_rx_id = addpath_id;

// 		/* add the route entry to route node*/
// 		bgp_path_info_add(dest, pi);
// 		*entry = pi;
// 	} else {
// 		tmp_pi = local_pi;
// 		if (!attrhash_cmp(tmp_pi->attr, attr)) {

// 			/* attribute changed */
// 			*route_changed = 1;

// 			/* if the asn values are different, copy the asn of
// 			 * source vrf to the target (evpn) vrf entry.
// 			 */
// 			if (bgp_vrf->as != bgp_evpn->as) {
// 				new_aspath = aspath_dup(static_attr.aspath);
// 				new_aspath = aspath_add_seq(new_aspath, bgp_vrf->as);
// 				static_attr.aspath = new_aspath;
// 			}
// 			/* The attribute has changed. */
// 			/* Add (or update) attribute to hash. */
// 			attr_new = bgp_attr_intern(&static_attr);
// 			bgp_attr_flush(&static_attr);
// 			bgp_path_info_set_flag(dest, tmp_pi,
// 					       BGP_PATH_ATTR_CHANGED);

// 			/* Restore route, if needed. */
// 			if (CHECK_FLAG(tmp_pi->flags, BGP_PATH_REMOVED))
// 				bgp_path_info_restore(dest, tmp_pi);

// 			/* Unintern existing, set to new. */
// 			bgp_attr_unintern(&tmp_pi->attr);
// 			tmp_pi->attr = attr_new;
// 			tmp_pi->uptime = monotime(NULL);
// 			tmp_pi->addpath_rx_id = addpath_id;
// 		}
// 		*entry = local_pi;
// 	}
// 	return 0;
// }

// /* update evpn type-5 route entry */
// static int update_evpn_type5_route(struct bgp *bgp_vrf, struct prefix_evpn *evp,
// 				   struct attr *src_attr, afi_t src_afi, safi_t src_safi,
// 				   uint32_t addpath_id)
// {
// 	afi_t afi = AFI_L2VPN;
// 	safi_t safi = SAFI_EVPN;
// 	struct attr attr;
// 	struct bgp_dest *dest = NULL;
// 	struct bgp *bgp_evpn = NULL;
// 	int route_changed = 0;
// 	struct bgp_path_info *pi = NULL;

// 	bgp_evpn = bgp_get_evpn();
// 	if (!bgp_evpn)
// 		return 0;

// 	/* Build path attribute for this route - use the source attr, if
// 	 * present, else treat as locally originated.
// 	 */
// 	if (src_attr)
// 		attr = *src_attr;
// 	else {
// 		memset(&attr, 0, sizeof(attr));
// 		bgp_attr_default_set(&attr, bgp_vrf, BGP_ORIGIN_IGP);
// 	}

// 	/* Advertise Primary IP (PIP) is enabled, send individual
// 	 * IP (default instance router-id) as nexthop.
// 	 * PIP is disabled or vrr interface is not present
// 	 * use anycast-IP as nexthop and anycast RMAC.
// 	 */
// 	if (!bgp_vrf->evpn_info->advertise_pip ||
// 	    (!bgp_vrf->evpn_info->is_anycast_mac)) {
// 		attr.nexthop = bgp_vrf->originator_ip;
// 		attr.mp_nexthop_global_in = bgp_vrf->originator_ip;
// 		memcpy(&attr.rmac, &bgp_vrf->rmac, ETH_ALEN);
// 	} else {
// 		/* copy sys rmac */
// 		memcpy(&attr.rmac, &bgp_vrf->evpn_info->pip_rmac, ETH_ALEN);
// 		if (bgp_vrf->evpn_info->pip_ip.s_addr != INADDR_ANY) {
// 			attr.nexthop = bgp_vrf->evpn_info->pip_ip;
// 			attr.mp_nexthop_global_in = bgp_vrf->evpn_info->pip_ip;
// 		} else if (bgp_vrf->evpn_info->pip_ip.s_addr == INADDR_ANY)
// 			if (bgp_debug_zebra(NULL))
// 				zlog_debug(
// 					"VRF %s evp %pFX advertise-pip primary ip is not configured",
// 					vrf_id_to_name(bgp_vrf->vrf_id), evp);
// 	}

// 	if (bgp_debug_zebra(NULL))
// 		zlog_debug(
// 			"VRF %s type-5 route evp %pFX RMAC %pEA nexthop %pI4",
// 			vrf_id_to_name(bgp_vrf->vrf_id), evp, &attr.rmac,
// 			&attr.nexthop);

// 	frrtrace(4, frr_bgp, evpn_advertise_type5, bgp_vrf->vrf_id, evp,
// 		 &attr.rmac, attr.nexthop);

// 	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;

// 	if (src_afi == AFI_IP6 &&
// 	    CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
// 		       BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP)) {
// 		if (src_attr &&
// 		    !IN6_IS_ADDR_UNSPECIFIED(&src_attr->mp_nexthop_global)) {
// 			struct bgp_route_evpn *bre =
// 				XCALLOC(MTYPE_BGP_EVPN_OVERLAY,
// 					sizeof(struct bgp_route_evpn));

// 			bre->type = OVERLAY_INDEX_GATEWAY_IP;
// 			SET_IPADDR_V6(&bre->gw_ip);
// 			memcpy(&bre->gw_ip.ipaddr_v6,
// 			       &src_attr->mp_nexthop_global,
// 			       sizeof(struct in6_addr));
// 			bgp_attr_set_evpn_overlay(&attr, bre);
// 		}
// 	} else if (src_afi == AFI_IP &&
// 		   CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
// 			      BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP)) {
// 		if (src_attr && src_attr->nexthop.s_addr != 0) {
// 			struct bgp_route_evpn *bre =
// 				XCALLOC(MTYPE_BGP_EVPN_OVERLAY,
// 					sizeof(struct bgp_route_evpn));

// 			bre->type = OVERLAY_INDEX_GATEWAY_IP;
// 			SET_IPADDR_V4(&bre->gw_ip);
// 			memcpy(&bre->gw_ip.ipaddr_v4, &src_attr->nexthop,
// 			       sizeof(struct in_addr));
// 			bgp_attr_set_evpn_overlay(&attr, bre);
// 		}
// 	}

// 	/* Setup RT and encap extended community */
// 	build_evpn_type5_route_extcomm(bgp_vrf, &attr);

// 	/* get the route node in global table */
// 	dest = bgp_evpn_global_node_get(bgp_evpn->rib[afi][safi], afi, safi,
// 					evp, &bgp_vrf->vrf_prd, NULL);
// 	assert(dest);

// 	/* create or update the route entry within the route node */
// 	update_evpn_type5_route_entry(bgp_evpn, bgp_vrf, afi, safi, dest, &attr, &route_changed,
// 				      &pi, addpath_id);

// 	/* schedule for processing and unlock node */
// 	if (route_changed) {
// 		bgp_process(bgp_evpn, dest, pi, afi, safi);
// 		bgp_dest_unlock_node(dest);
// 	}

// 	/* uninten temporary */
// 	if (!src_attr)
// 		aspath_unintern(&attr.aspath);
// 	return 0;
// }

// static void bgp_evpn_get_sync_info(struct bgp *bgp, esi_t *esi,
// 				   struct bgp_dest *dest, uint32_t loc_seq,
// 				   uint32_t *max_sync_seq, bool *active_on_peer,
// 				   bool *peer_router, bool *proxy_from_peer,
// 				   const struct ethaddr *mac)
// {
// 	struct bgp_path_info *tmp_pi;
// 	struct bgp_path_info *second_best_path = NULL;
// 	uint32_t tmp_mm_seq = 0;
// 	esi_t *tmp_esi;
// 	int paths_eq;
// 	struct ethaddr *tmp_mac;
// 	bool mac_cmp = false;
// 	struct prefix_evpn *evp = (struct prefix_evpn *)&dest->rn->p;


// 	/* mac comparison is not needed for MAC-only routes */
// 	if (mac && !is_evpn_prefix_ipaddr_none(evp))
// 		mac_cmp = true;

// 	/* find the best non-local path. a local path can only be present
// 	 * as best path
// 	 */
// 	for (tmp_pi = bgp_dest_get_bgp_path_info(dest); tmp_pi;
// 	     tmp_pi = tmp_pi->next) {
// 		if (tmp_pi->sub_type != BGP_ROUTE_IMPORTED ||
// 			!CHECK_FLAG(tmp_pi->flags, BGP_PATH_VALID))
// 			continue;

// 		/* ignore paths that have a different mac */
// 		if (mac_cmp) {
// 			tmp_mac = evpn_type2_path_info_get_mac(tmp_pi);
// 			if (memcmp(mac, tmp_mac, sizeof(*mac)))
// 				continue;
// 		}

// 		if (bgp_evpn_path_info_cmp(bgp, tmp_pi, second_best_path,
// 					   &paths_eq, false))
// 			second_best_path = tmp_pi;
// 	}

// 	if (!second_best_path)
// 		return;

// 	tmp_esi = bgp_evpn_attr_get_esi(second_best_path->attr);
// 	/* if this has the same ES desination as the local path
// 	 * it is a sync path
// 	 */
// 	if (!memcmp(esi, tmp_esi, sizeof(esi_t))) {
// 		tmp_mm_seq = mac_mobility_seqnum(second_best_path->attr);
// 		if (tmp_mm_seq < loc_seq)
// 			return;

// 		/* we have a non-proxy path from the ES peer.  */
// 		if (second_best_path->attr->es_flags &
// 					ATTR_ES_PROXY_ADVERT) {
// 			*proxy_from_peer = true;
// 		} else {
// 			*active_on_peer = true;
// 		}

// 		if (CHECK_FLAG(second_best_path->attr->evpn_flags,
// 			       ATTR_EVPN_FLAG_ROUTER))
// 			*peer_router = true;

// 		/* we use both proxy and non-proxy imports to
// 		 * determine the max sync sequence
// 		 */
// 		if (tmp_mm_seq > *max_sync_seq)
// 			*max_sync_seq = tmp_mm_seq;
// 	}
// }

// /* Bubble up sync-info from all paths (non-best) to the local-path.
//  * This is need for MM sequence number syncing and proxy advertisement.
//  * Note: The local path can only exist as a best path in the
//  * VPN route table. It will take precedence over all sync paths.
//  */
// static void update_evpn_route_entry_sync_info(struct bgp *bgp,
// 					      struct bgp_dest *dest,
// 					      struct attr *attr,
// 					      uint32_t loc_seq, bool setup_sync,
// 					      const struct ethaddr *mac)
// {
// 	esi_t *esi;
// 	struct prefix_evpn *evp =
// 		(struct prefix_evpn *)bgp_dest_get_prefix(dest);

// 	if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
// 		return;

// 	esi = bgp_evpn_attr_get_esi(attr);
// 	if (bgp_evpn_is_esi_valid(esi)) {
// 		if (setup_sync) {
// 			uint32_t max_sync_seq = 0;
// 			bool active_on_peer = false;
// 			bool peer_router = false;
// 			bool proxy_from_peer = false;

// 			bgp_evpn_get_sync_info(bgp, esi, dest, loc_seq,
// 					       &max_sync_seq, &active_on_peer,
// 					       &peer_router, &proxy_from_peer,
// 					       mac);
// 			attr->mm_sync_seqnum = max_sync_seq;
// 			if (active_on_peer)
// 				SET_FLAG(attr->es_flags, ATTR_ES_PEER_ACTIVE);
// 			else
// 				UNSET_FLAG(attr->es_flags, ATTR_ES_PEER_ACTIVE);
// 			if (proxy_from_peer)
// 				SET_FLAG(attr->es_flags, ATTR_ES_PEER_PROXY);
// 			else
// 				UNSET_FLAG(attr->es_flags, ATTR_ES_PEER_PROXY);
// 			if (peer_router)
// 				SET_FLAG(attr->es_flags, ATTR_ES_PEER_ROUTER);
// 			else
// 				UNSET_FLAG(attr->es_flags, ATTR_ES_PEER_ROUTER);

// 			if (BGP_DEBUG(evpn_mh, EVPN_MH_RT)) {
// 				char esi_buf[ESI_STR_LEN];

// 				zlog_debug("setup sync info for %pFX es %s max_seq %d %s%s%s",
// 					   evp,
// 					   esi_to_str(esi, esi_buf,
// 						      sizeof(esi_buf)),
// 					   max_sync_seq,
// 					   CHECK_FLAG(attr->es_flags,
// 						      ATTR_ES_PEER_ACTIVE)
// 						   ? "peer-active "
// 						   : "",
// 					   CHECK_FLAG(attr->es_flags,
// 						      ATTR_ES_PEER_PROXY)
// 						   ? "peer-proxy "
// 						   : "",
// 					   CHECK_FLAG(attr->es_flags,
// 						      ATTR_ES_PEER_ROUTER)
// 						   ? "peer-router "
// 						   : "");
// 			}
// 		}
// 	} else {
// 		attr->mm_sync_seqnum = 0;
// 		UNSET_FLAG(attr->es_flags, ATTR_ES_PEER_ACTIVE);
// 		UNSET_FLAG(attr->es_flags, ATTR_ES_PEER_PROXY);
// 	}
// }

// /*
//  * Check if the route is a type-2 MAC-IP route with a valid global address
//  * (IPv4 or non-link-local IPv6) and the VPN has a valid L3 VNI configured.
//  */
// static inline bool bgp_evpn_is_macip_with_l3vni(struct bgpevpn *vpn, const struct prefix_evpn *p)
// {
// 	return p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE &&
// 	       (is_evpn_prefix_ipaddr_v4(p) ||
// 		(is_evpn_prefix_ipaddr_v6(p) &&
// 		 !IN6_IS_ADDR_LINKLOCAL(&p->prefix.macip_addr.ip.ipaddr_v6))) &&
// 	       CHECK_FLAG(vpn->flags, VNI_FLAG_USE_TWO_LABELS) && bgpevpn_get_l3vni(vpn);
// }

// /*
//  * While adding l3-attrs such as rmac and l3 RTs we need an added check for ES
//  * as well along with checking for mac-ip with l3vni.
//  */
// static inline bool bgp_evpn_route_add_l3_attrs_ok(struct bgpevpn *vpn, const struct prefix_evpn *p,
// 						  esi_t *esi)
// {
// 	return bgp_evpn_is_macip_with_l3vni(vpn, p) && bgp_evpn_es_add_l3_attrs_ok(esi);
// }

// /*
//  * Create or update EVPN route entry. This could be in the VNI route tables
//  * or the global route table.
//  */
// static int update_evpn_route_entry(struct bgp *bgp, struct bgpevpn *vpn,
// 				   afi_t afi, safi_t safi,
// 				   struct bgp_dest *dest, struct attr *attr,
// 				   const struct ethaddr *mac,
// 				   const struct ipaddr *ip, int add,
// 				   struct bgp_path_info **pi, uint8_t flags,
// 				   uint32_t seq, bool vpn_rt, bool *old_is_sync)
// {
// 	struct bgp_path_info *tmp_pi;
// 	struct bgp_path_info *local_pi;
// 	struct attr *attr_new;
// 	struct attr local_attr;
// 	struct bgp_labels bgp_labels = {};
// 	int route_change = 1;
// 	const struct prefix_evpn *evp;

// 	*pi = NULL;
// 	evp = (const struct prefix_evpn *)bgp_dest_get_prefix(dest);

// 	/* See if this is an update of an existing route, or a new add. */
// 	local_pi = bgp_evpn_route_get_local_path(bgp, dest, 0);

// 	/* If route doesn't exist already, create a new one, if told to.
// 	 * Otherwise act based on whether the attributes of the route have
// 	 * changed or not.
// 	 */
// 	if (!local_pi && !add)
// 		return 0;

// 	if (old_is_sync && local_pi)
// 		*old_is_sync = bgp_evpn_attr_is_sync(local_pi->attr);

// 	/* if a local path is being added with a non-zero esi look
// 	 * for SYNC paths from ES peers and bubble up the sync-info
// 	 */
// 	update_evpn_route_entry_sync_info(bgp, dest, attr, seq, vpn_rt, mac);

// 	/* For non-GW MACs, update MAC mobility seq number, if needed. */
// 	if (seq && !CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_GW))
// 		add_mac_mobility_to_attr(seq, attr);

// 	if (!local_pi) {
// 		local_attr = *attr;

// 		/* Extract MAC mobility sequence number, if any. */
// 		local_attr.mm_seqnum = bgp_attr_mac_mobility_seqnum(&local_attr);

// 		/* Add (or update) attribute to hash. */
// 		attr_new = bgp_attr_intern(&local_attr);

// 		/* Create new route with its attribute. */
// 		tmp_pi = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0,
// 				   bgp->peer_self, attr_new, dest);
// 		SET_FLAG(tmp_pi->flags, BGP_PATH_VALID);
// 		bgp_path_info_extra_get(tmp_pi);

// 		/* The VNI goes into the 'label' field of the route */
// 		vni2label(vpn->vni, &bgp_labels.label[0]);
// 		bgp_labels.num_labels = 1;

// 		/* Type-2 routes may carry a second VNI - the L3-VNI.
// 		 * Only attach second label if we are advertising two labels for
// 		 * type-2 routes.
// 		 */
// 		if (bgp_evpn_is_macip_with_l3vni(vpn, evp)) {
// 			vni_t l3vni;

// 			l3vni = bgpevpn_get_l3vni(vpn);
// 			if (l3vni) {
// 				vni2label(l3vni, &bgp_labels.label[1]);
// 				bgp_labels.num_labels++;
// 			}
// 		}

// 		if (!bgp_path_info_labels_same(tmp_pi, &bgp_labels.label[0],
// 					       bgp_labels.num_labels)) {
// 			bgp_labels_unintern(&tmp_pi->extra->labels);
// 			tmp_pi->extra->labels = bgp_labels_intern(&bgp_labels);
// 		}

// 		if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
// 			if (mac)
// 				evpn_type2_path_info_set_mac(tmp_pi, *mac);
// 			else if (ip)
// 				evpn_type2_path_info_set_ip(tmp_pi, *ip);
// 		}

// 		/* Mark route as self type-2 route */
// 		if (flags && CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_SVI_IP))
// 			tmp_pi->extra->evpn->af_flags =
// 				BGP_EVPN_MACIP_TYPE_SVI_IP;
// 		bgp_path_info_add(dest, tmp_pi);
// 	} else {
// 		tmp_pi = local_pi;
// 		if (!CHECK_FLAG(tmp_pi->flags, BGP_PATH_REMOVED) && attrhash_cmp(tmp_pi->attr, attr))
// 			route_change = 0;
// 		else {
// 			/*
// 			 * The attributes have changed, type-2 routes needs to
// 			 * be advertised with right labels.
// 			 */
// 			vni2label(vpn->vni, &bgp_labels.label[0]);
// 			bgp_labels.num_labels = 1;
// 			if (bgp_evpn_is_macip_with_l3vni(vpn, evp)) {
// 				vni_t l3vni;

// 				l3vni = bgpevpn_get_l3vni(vpn);
// 				if (l3vni) {
// 					vni2label(l3vni, &bgp_labels.label[1]);
// 					bgp_labels.num_labels++;
// 				}
// 			}
// 			if (!bgp_path_info_labels_same(tmp_pi,
// 						       &bgp_labels.label[0],
// 						       bgp_labels.num_labels)) {
// 				bgp_labels_unintern(&tmp_pi->extra->labels);
// 				tmp_pi->extra->labels =
// 					bgp_labels_intern(&bgp_labels);
// 			}

// 			if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
// 				if (mac)
// 					evpn_type2_path_info_set_mac(tmp_pi,
// 								     *mac);
// 				else if (ip)
// 					evpn_type2_path_info_set_ip(tmp_pi,
// 								    *ip);
// 			}

// 			/* The attribute has changed. */
// 			/* Add (or update) attribute to hash. */
// 			local_attr = *attr;
// 			bgp_path_info_set_flag(dest, tmp_pi,
// 					       BGP_PATH_ATTR_CHANGED);

// 			/* Extract MAC mobility sequence number, if any. */
// 			local_attr.mm_seqnum =
// 				bgp_attr_mac_mobility_seqnum(&local_attr);

// 			attr_new = bgp_attr_intern(&local_attr);

// 			/* Restore route, if needed. */
// 			if (CHECK_FLAG(tmp_pi->flags, BGP_PATH_REMOVED))
// 				bgp_path_info_restore(dest, tmp_pi);

// 			/* Unintern existing, set to new. */
// 			bgp_attr_unintern(&tmp_pi->attr);
// 			tmp_pi->attr = attr_new;
// 			tmp_pi->uptime = monotime(NULL);
// 		}
// 	}

// 	/* local MAC-IP routes in the VNI table are linked to
// 	 * the destination ES
// 	 */
// 	if (route_change && vpn_rt
// 	    && (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE))
// 		bgp_evpn_path_es_link(tmp_pi, vpn->vni,
// 				      bgp_evpn_attr_get_esi(tmp_pi->attr));

// 	/* Return back the route entry. */
// 	*pi = tmp_pi;
// 	return route_change;
// }

// static void evpn_zebra_reinstall_best_route(struct bgp *bgp,
// 					    struct bgpevpn *vpn,
// 					    struct bgp_dest *dest)
// {
// 	struct bgp_path_info *tmp_ri;
// 	struct bgp_path_info *curr_select = NULL;

// 	for (tmp_ri = bgp_dest_get_bgp_path_info(dest); tmp_ri;
// 	     tmp_ri = tmp_ri->next) {
// 		if (CHECK_FLAG(tmp_ri->flags, BGP_PATH_SELECTED)) {
// 			curr_select = tmp_ri;
// 			break;
// 		}
// 	}

// 	if (curr_select && curr_select->type == ZEBRA_ROUTE_BGP &&
// 	    (curr_select->sub_type == BGP_ROUTE_IMPORTED ||
// 	     bgp_evpn_attr_is_sync(curr_select->attr))) {
// 		if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS))
// 			evpn_zebra_install(bgp, vpn,
// 					   (const struct prefix_evpn *)
// 						   bgp_dest_get_prefix(dest),
// 					   curr_select);
// 		else
// 			bgp_zebra_route_install(dest, curr_select, bgp, true,
// 						vpn, false);
// 	}
// }

// /*
//  * If the local route was not selected evict it and tell zebra to re-add
//  * the best remote dest.
//  *
//  * Typically a local path added by zebra is expected to be selected as
//  * best. In which case when a remote path wins as best (later)
//  * evpn_route_select_install itself evicts the older-local-best path.
//  *
//  * However if bgp's add and zebra's add cross paths (race condition) it
//  * is possible that the local path is no longer the "older" best path.
//  * It is a path that was never designated as best and hence requires
//  * additional handling to prevent bgp from injecting and holding on to a
//  * non-best local path.
//  */
// static struct bgp_dest *
// evpn_cleanup_local_non_best_route(struct bgp *bgp, struct bgpevpn *vpn,
// 				  struct bgp_dest *dest,
// 				  struct bgp_path_info *local_pi)
// {
// 	/* local path was not picked as the winner; kick it out */
// 	if (bgp_debug_zebra(NULL))
// 		zlog_debug("evicting local evpn prefix %pBD as remote won",
// 			   dest);

// 	evpn_delete_old_local_route(bgp, vpn, dest, local_pi, NULL);

// 	/* tell zebra to re-add the best remote path */
// 	evpn_zebra_reinstall_best_route(bgp, vpn, dest);

// 	return bgp_path_info_reap(dest, local_pi);
// }

// /*
//  * Create or update EVPN route (of type based on prefix) for specified VNI
//  * and schedule for processing.
//  */
// static int update_evpn_route(struct bgp *bgp, struct bgpevpn *vpn,
// 			     struct prefix_evpn *p, uint8_t flags,
// 			     uint32_t seq, esi_t *esi)
// {
// 	struct bgp_dest *dest;
// 	struct attr attr;
// 	struct attr *attr_new;
// 	bool add_l3_attrs = false;
// 	struct bgp_path_info *pi;
// 	afi_t afi = AFI_L2VPN;
// 	safi_t safi = SAFI_EVPN;
// 	int route_change;
// 	bool old_is_sync = false;
// 	bool mac_only = false;
// 	struct ecommunity *macvrf_soo = NULL;

// 	memset(&attr, 0, sizeof(attr));

// 	/* Build path-attribute for this route. */
// 	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
// 	attr.nexthop = vpn->originator_ip;
// 	attr.mp_nexthop_global_in = vpn->originator_ip;
// 	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
// 	if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY))
// 		SET_FLAG(attr.evpn_flags, ATTR_EVPN_FLAG_STICKY);
// 	if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_GW))
// 		SET_FLAG(attr.evpn_flags, ATTR_EVPN_FLAG_DEFAULT_GW);
// 	if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_ROUTER_FLAG))
// 		SET_FLAG(attr.evpn_flags, ATTR_EVPN_FLAG_ROUTER);
// 	if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_PROXY_ADVERT))
// 		SET_FLAG(attr.es_flags, ATTR_ES_PROXY_ADVERT);

// 	if (esi && bgp_evpn_is_esi_valid(esi)) {
// 		memcpy(&attr.esi, esi, sizeof(esi_t));
// 		SET_FLAG(attr.es_flags, ATTR_ES_IS_LOCAL);
// 	}

// 	/* PMSI is only needed for type-3 routes */
// 	if (p->prefix.route_type == BGP_EVPN_IMET_ROUTE) {
// 		SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_PMSI_TUNNEL));
// 		bgp_attr_set_pmsi_tnl_type(&attr, PMSI_TNLTYPE_INGR_REPL);
// 	}

// 	/* router mac is only needed for type-2 routes here. */
// 	if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
// 		uint8_t af_flags = 0;

// 		if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_SVI_IP))
// 			SET_FLAG(af_flags, BGP_EVPN_MACIP_TYPE_SVI_IP);

// 		bgp_evpn_get_rmac_nexthop(vpn, p, &attr, af_flags);
// 	}

// 	if (bgp_debug_zebra(NULL)) {
// 		char buf3[ESI_STR_LEN];

// 		zlog_debug(
// 			"VRF %s vni %u type-%u route evp %pFX RMAC %pEA nexthop %pI4 esi %s",
// 			vpn->bgp_vrf ? vrf_id_to_name(vpn->bgp_vrf->vrf_id)
// 				     : "None",
// 			vpn->vni, p->prefix.route_type, p, &attr.rmac,
// 			&attr.mp_nexthop_global_in,
// 			esi_to_str(esi, buf3, sizeof(buf3)));
// 	}

// 	vni2label(vpn->vni, &(attr.label));

// 	/* Include L3 VNI related attributes (RTs, RMAC and MPLS Label2)
// 	 * for type-2 routes, if they're IPv4 or IPv6 global addresses and
// 	 * we're advertising L3VNI with these routes.
// 	 */
// 	add_l3_attrs = bgp_evpn_route_add_l3_attrs_ok(vpn, p,
// 						      CHECK_FLAG(attr.es_flags, ATTR_ES_IS_LOCAL)
// 							      ? &attr.esi
// 							      : NULL);

// 	if (bgp->evpn_info)
// 		macvrf_soo = bgp->evpn_info->soo;

// 	/* Set up extended community. */
// 	build_evpn_route_extcomm(vpn, &attr, add_l3_attrs, macvrf_soo);

// 	/* First, create (or fetch) route node within the VNI.
// 	 * NOTE: There is no RD here.
// 	 */
// 	dest = bgp_evpn_vni_node_get(vpn, p, NULL);

// 	if ((p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) &&
// 	    (is_evpn_prefix_ipaddr_none(p) == true))
// 		mac_only = true;

// 	/* Create or update route entry. */
// 	route_change = update_evpn_route_entry(
// 		bgp, vpn, afi, safi, dest, &attr,
// 		(mac_only ? NULL : &p->prefix.macip_addr.mac), NULL /* ip */, 1,
// 		&pi, flags, seq, true /* setup_sync */, &old_is_sync);
// 	assert(pi);
// 	attr_new = pi->attr;

// 	/* lock ri to prevent freeing in evpn_route_select_install */
// 	bgp_path_info_lock(pi);

//        /* Perform route selection. Normally, the local route in the
//         * VNI is expected to win and be the best route. However, if
//         * there is a race condition where a host moved from local to
//         * remote and the remote route was received in BGP just prior
//         * to the local MACIP notification from zebra, the remote
//         * route would win, and we should evict the defunct local route
//         * and (re)install the remote route into zebra.
// 	*/
// 	evpn_route_select_install(bgp, vpn, dest, pi);
// 	/*
// 	 * If the new local route was not selected evict it and tell zebra
// 	 * to re-add the best remote dest. BGP doesn't retain non-best local
// 	 * routes.
// 	 */
// 	if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
// 		route_change = 0;
// 	} else {
// 		if (!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)) {
// 			route_change = 0;
// 			dest = evpn_cleanup_local_non_best_route(bgp, vpn, dest,
// 								 pi);
// 		} else {
// 			bool new_is_sync;

// 			/* If the local path already existed and is still the
// 			 * best path we need to also check if it transitioned
// 			 * from being a sync path to a non-sync path. If it
// 			 * it did we need to notify zebra that the sync-path
// 			 * has been removed.
// 			 */
// 			new_is_sync = bgp_evpn_attr_is_sync(pi->attr);
// 			if (!new_is_sync && old_is_sync) {
// 				if (CHECK_FLAG(bgp->flags,
// 					       BGP_FLAG_DELETE_IN_PROGRESS))
// 					evpn_zebra_uninstall(bgp, vpn, p, pi,
// 							     true);
// 				else
// 					bgp_zebra_route_install(dest, pi, bgp,
// 								false, vpn,
// 								true);
// 			}
// 		}
// 	}
// 	bgp_path_info_unlock(pi);

// 	if (dest)
// 		bgp_dest_unlock_node(dest);

// 	/* If this is a new route or some attribute has changed, export the
// 	 * route to the global table. The route will be advertised to peers
// 	 * from there. Note that this table is a 2-level tree (RD-level +
// 	 * Prefix-level) similar to L3VPN routes.
// 	 */
// 	if (route_change) {
// 		struct bgp_path_info *global_pi;

// 		dest = bgp_evpn_global_node_get(bgp->rib[afi][safi], afi, safi,
// 						p, &vpn->prd, NULL);
// 		update_evpn_route_entry(
// 			bgp, vpn, afi, safi, dest, attr_new, NULL /* mac */,
// 			NULL /* ip */, 1, &global_pi, flags, seq,
// 			false /* setup_sync */, NULL /* old_is_sync */);

// 		/* Schedule for processing and unlock node. */
// 		bgp_process(bgp, dest, global_pi, afi, safi);
// 		bgp_dest_unlock_node(dest);
// 	}

// 	/* Unintern temporary. */
// 	aspath_unintern(&attr.aspath);

// 	return 0;
// }

// /*
//  * Delete EVPN route entry.
//  * The entry can be in ESI/VNI table or the global table.
//  */
// struct bgp_path_info *delete_evpn_route_entry(struct bgp *bgp, afi_t afi, safi_t safi,
// 					      struct bgp_dest *dest, uint32_t addpath_id)
// {
// 	struct bgp_path_info *pi = NULL;

// 	/* Now, find matching route. */
// 	pi = bgp_evpn_route_get_local_path(bgp, dest, addpath_id);

// 	/* Mark route for delete. */
// 	if (pi)
// 		bgp_path_info_mark_for_delete(dest, pi);

// 	return pi;
// }

// /* Delete EVPN type5 route */
// static int delete_evpn_type5_route(struct bgp *bgp_vrf, struct prefix_evpn *evp,
// 				   uint32_t addpath_id)
// {
// 	afi_t afi = AFI_L2VPN;
// 	safi_t safi = SAFI_EVPN;
// 	struct bgp_dest *dest = NULL;
// 	struct bgp_path_info *pi = NULL;
// 	struct bgp *bgp_evpn = NULL; /* evpn bgp instance */

// 	bgp_evpn = bgp_get_evpn();
// 	if (!bgp_evpn)
// 		return 0;

// 	/* locate the global route entry for this type-5 prefix */
// 	dest = bgp_evpn_global_node_lookup(bgp_evpn->rib[afi][safi], safi, evp,
// 					   &bgp_vrf->vrf_prd, NULL);
// 	if (!dest)
// 		return 0;

// 	frrtrace(2, frr_bgp, evpn_withdraw_type5, bgp_vrf->vrf_id, evp);

// 	pi = delete_evpn_route_entry(bgp_evpn, afi, safi, dest, addpath_id);
// 	if (pi)
// 		bgp_process(bgp_evpn, dest, pi, afi, safi);
// 	bgp_dest_unlock_node(dest);
// 	return 0;
// }

// /*
//  * Delete EVPN route (of type based on prefix) for specified VNI and
//  * schedule for processing.
//  */
// static int delete_evpn_route(struct bgp *bgp, struct bgpevpn *vpn,
// 			     struct prefix_evpn *p)
// {
// 	struct bgp_dest *dest, *global_dest;
// 	struct bgp_path_info *pi;
// 	afi_t afi = AFI_L2VPN;
// 	safi_t safi = SAFI_EVPN;

// 	/* First, locate the route node within the VNI. If it doesn't exist,
// 	 * there
// 	 * is nothing further to do.
// 	 * NOTE: There is no RD here.
// 	 */
// 	dest = bgp_evpn_vni_node_lookup(vpn, p, NULL);
// 	if (!dest)
// 		return 0;

// 	/* Next, locate route node in the global EVPN routing table. Note that
// 	 * this table is a 2-level tree (RD-level + Prefix-level) similar to
// 	 * L3VPN routes.
// 	 */
// 	global_dest = bgp_evpn_global_node_lookup(bgp->rib[afi][safi], safi, p,
// 						  &vpn->prd, NULL);
// 	if (global_dest) {
// 		/* Delete route entry in the global EVPN table. */
// 		pi = delete_evpn_route_entry(bgp, afi, safi, global_dest, 0);

// 		/* Schedule for processing - withdraws to peers happen from
// 		 * this table.
// 		 */
// 		if (pi)
// 			bgp_process(bgp, global_dest, pi, afi, safi);
// 		bgp_dest_unlock_node(global_dest);
// 	}

// 	/* Delete route entry in the VNI route table. This can just be removed.
// 	 */
// 	pi = delete_evpn_route_entry(bgp, afi, safi, dest, 0);
// 	if (pi) {
// 		bgp_path_info_mark_for_delete(dest, pi);
// 		evpn_route_select_install(bgp, vpn, dest, pi);
// 	}

// 	/* dest should still exist due to locking make coverity happy */
// 	assert(dest);
// 	bgp_dest_unlock_node(dest);

// 	return 0;
// }

// void bgp_evpn_update_type2_route_entry(struct bgp *bgp, struct bgpevpn *vpn,
// 				       struct bgp_dest *dest,
// 				       struct bgp_path_info *local_pi,
// 				       const char *caller)
// {
// 	afi_t afi = AFI_L2VPN;
// 	safi_t safi = SAFI_EVPN;
// 	struct bgp_path_info *pi;
// 	struct attr attr;
// 	struct attr *attr_new;
// 	uint32_t seq;
// 	bool add_l3_attrs = false;
// 	struct bgp_dest *global_dest;
// 	struct bgp_path_info *global_pi;
// 	struct prefix_evpn evp;
// 	int route_change;
// 	bool old_is_sync = false;
// 	struct ecommunity *macvrf_soo = NULL;

// 	if (CHECK_FLAG(local_pi->flags, BGP_PATH_REMOVED))
// 		return;

// 	/*
// 	 * VNI table MAC-IP prefixes don't have MAC so make sure it's set from
// 	 * path info here.
// 	 */
// 	if (is_evpn_prefix_ipaddr_none((struct prefix_evpn *)&dest->rn->p)) {
// 		/* VNI MAC -> Global */
// 		evpn_type2_prefix_global_copy(
// 			&evp, (struct prefix_evpn *)&dest->rn->p, NULL /* mac */,
// 			evpn_type2_path_info_get_ip(local_pi));
// 	} else {
// 		/* VNI IP -> Global */
// 		evpn_type2_prefix_global_copy(
// 			&evp, (struct prefix_evpn *)&dest->rn->p,
// 			evpn_type2_path_info_get_mac(local_pi), NULL /* ip */);
// 	}

// 	/*
// 	 * Build attribute per local route as the MAC mobility and
// 	 * some other values could differ for different routes. The
// 	 * attributes will be shared in the hash table.
// 	 */
// 	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
// 	attr.nexthop = vpn->originator_ip;
// 	attr.mp_nexthop_global_in = vpn->originator_ip;
// 	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
// 	attr.evpn_flags = local_pi->attr->evpn_flags;
// 	attr.es_flags = local_pi->attr->es_flags;
// 	if (CHECK_FLAG(local_pi->attr->evpn_flags, ATTR_EVPN_FLAG_DEFAULT_GW)) {
// 		SET_FLAG(attr.evpn_flags, ATTR_EVPN_FLAG_DEFAULT_GW);
// 		if (is_evpn_prefix_ipaddr_v6(&evp))
// 			SET_FLAG(attr.evpn_flags, ATTR_EVPN_FLAG_ROUTER);
// 	}
// 	memcpy(&attr.esi, &local_pi->attr->esi, sizeof(esi_t));
// 	bgp_evpn_get_rmac_nexthop(vpn, &evp, &attr,
// 				  local_pi->extra->evpn->af_flags);
// 	vni2label(vpn->vni, &(attr.label));
// 	/* Add L3 VNI RTs and RMAC for non IPv6 link-local if
// 	 * using L3 VNI for type-2 routes also.
// 	 */
// 	add_l3_attrs = bgp_evpn_route_add_l3_attrs_ok(vpn, &evp,
// 						      CHECK_FLAG(attr.es_flags, ATTR_ES_IS_LOCAL)
// 							      ? &attr.esi
// 							      : NULL);

// 	if (bgp->evpn_info)
// 		macvrf_soo = bgp->evpn_info->soo;

// 	/* Set up extended community. */
// 	build_evpn_route_extcomm(vpn, &attr, add_l3_attrs, macvrf_soo);
// 	seq = mac_mobility_seqnum(local_pi->attr);

// 	if (bgp_debug_zebra(NULL)) {
// 		char buf3[ESI_STR_LEN];

// 		zlog_debug(
// 			"VRF %s vni %u evp %pFX RMAC %pEA nexthop %pI4 esi %s esf 0x%x from %s",
// 			vpn->bgp_vrf ? vrf_id_to_name(vpn->bgp_vrf->vrf_id)
// 				     : " ",
// 			vpn->vni, &evp, &attr.rmac, &attr.mp_nexthop_global_in,
// 			esi_to_str(&attr.esi, buf3, sizeof(buf3)),
// 			attr.es_flags, caller);
// 	}

// 	/* Update the route entry. */
// 	route_change = update_evpn_route_entry(
// 		bgp, vpn, afi, safi, dest, &attr, NULL /* mac */, NULL /* ip */,
// 		0, &pi, 0, seq, true /* setup_sync */, &old_is_sync);

// 	assert(pi);
// 	attr_new = pi->attr;
// 	/* lock ri to prevent freeing in evpn_route_select_install */
// 	bgp_path_info_lock(pi);

// 	/* Perform route selection. Normally, the local route in the
// 	 * VNI is expected to win and be the best route. However,
// 	 * under peculiar situations (e.g., tunnel (next hop) IP change
// 	 * that causes best selection to be based on next hop), a
// 	 * remote route could win. If the local route is the best,
// 	 * ensure it is updated in the global EVPN route table and
// 	 * advertised to peers; otherwise, ensure it is evicted and
// 	 * (re)install the remote route into zebra.
// 	 */
// 	evpn_route_select_install(bgp, vpn, dest, pi);

// 	if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
// 		route_change = 0;
// 	} else {
// 		if (!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)) {
// 			route_change = 0;
// 			evpn_cleanup_local_non_best_route(bgp, vpn, dest, pi);
// 		} else {
// 			bool new_is_sync;

// 			/* If the local path already existed and is still the
// 			 * best path we need to also check if it transitioned
// 			 * from being a sync path to a non-sync path. If it
// 			 * it did we need to notify zebra that the sync-path
// 			 * has been removed.
// 			 */
// 			new_is_sync = bgp_evpn_attr_is_sync(pi->attr);
// 			if (!new_is_sync && old_is_sync) {
// 				if (CHECK_FLAG(bgp->flags,
// 					       BGP_FLAG_DELETE_IN_PROGRESS))
// 					(void)evpn_zebra_uninstall(bgp, vpn,
// 								   &evp, pi,
// 								   true);
// 				else
// 					bgp_zebra_route_install(dest, pi, bgp,
// 								false, vpn,
// 								true);
// 			}
// 		}
// 	}


// 	/* unlock pi */
// 	bgp_path_info_unlock(pi);

// 	if (route_change) {
// 		/* Update route in global routing table. */
// 		global_dest = bgp_evpn_global_node_get(
// 			bgp->rib[afi][safi], afi, safi, &evp, &vpn->prd, NULL);
// 		assert(global_dest);
// 		update_evpn_route_entry(
// 			bgp, vpn, afi, safi, global_dest, attr_new,
// 			NULL /* mac */, NULL /* ip */, 0, &global_pi, 0,
// 			mac_mobility_seqnum(attr_new), false /* setup_sync */,
// 			NULL /* old_is_sync */);

// 		/* Schedule for processing and unlock node. */
// 		bgp_process(bgp, global_dest, global_pi, afi, safi);
// 		bgp_dest_unlock_node(global_dest);
// 	}

// 	/* Unintern temporary. */
// 	aspath_unintern(&attr.aspath);
// }

// static void update_type2_route(struct bgp *bgp, struct bgpevpn *vpn,
// 			       struct bgp_dest *dest)
// {
// 	struct bgp_path_info *tmp_pi;

// 	const struct prefix_evpn *evp =
// 		(const struct prefix_evpn *)bgp_dest_get_prefix(dest);

// 	if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
// 		return;

// 	/* Identify local route. */
// 	tmp_pi = bgp_evpn_route_get_local_path(bgp, dest, 0);
// 	if (!tmp_pi)
// 		return;

// 	bgp_evpn_update_type2_route_entry(bgp, vpn, dest, tmp_pi, __func__);
// }

// /*
//  * Update all type-2 (MACIP) local routes for this VNI - these should also
//  * be scheduled for advertise to peers.
//  */
// static void update_all_type2_routes(struct bgp *bgp, struct bgpevpn *vpn)
// {
// 	struct bgp_dest *dest;

// 	/* Walk this VNI's route MAC & IP table and update local type-2
// 	 * routes. For any routes updated, update corresponding entry in the
// 	 * global table too.
// 	 */
// 	for (dest = bgp_table_top(vpn->mac_table); dest;
// 	     dest = bgp_route_next(dest))
// 		update_type2_route(bgp, vpn, dest);

// 	for (dest = bgp_table_top(vpn->ip_table); dest;
// 	     dest = bgp_route_next(dest))
// 		update_type2_route(bgp, vpn, dest);
// }

// /*
//  * Delete all type-2 (MACIP) local routes for this VNI - only from the
//  * global routing table. These are also scheduled for withdraw from peers.
//  */
// static void delete_global_type2_routes(struct bgp *bgp, struct bgpevpn *vpn)
// {
// 	afi_t afi;
// 	safi_t safi;
// 	struct bgp_dest *rddest, *dest;
// 	struct bgp_table *table;
// 	struct bgp_path_info *pi;

// 	afi = AFI_L2VPN;
// 	safi = SAFI_EVPN;

// 	rddest = bgp_node_lookup(bgp->rib[afi][safi],
// 				 (struct prefix *)&vpn->prd);
// 	if (rddest) {
// 		table = bgp_dest_get_bgp_table_info(rddest);
// 		for (dest = bgp_table_top(table); dest;
// 		     dest = bgp_route_next(dest)) {
// 			const struct prefix_evpn *evp =
// 				(const struct prefix_evpn *)bgp_dest_get_prefix(
// 					dest);

// 			if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
// 				continue;

// 			pi = delete_evpn_route_entry(bgp, afi, safi, dest, 0);
// 			if (pi)
// 				bgp_process(bgp, dest, pi, afi, safi);
// 		}

// 		/* Unlock RD node. */
// 		bgp_dest_unlock_node(rddest);
// 	}
// }

// static struct bgp_dest *delete_vni_type2_route(struct bgp *bgp,
// 					       struct bgp_dest *dest)
// {
// 	struct bgp_path_info *pi;
// 	afi_t afi = AFI_L2VPN;
// 	safi_t safi = SAFI_EVPN;

// 	const struct prefix_evpn *evp =
// 		(const struct prefix_evpn *)bgp_dest_get_prefix(dest);

// 	if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
// 		return dest;

// 	pi = delete_evpn_route_entry(bgp, afi, safi, dest, 0);

// 	/* Route entry in local table gets deleted immediately. */
// 	if (pi)
// 		dest = bgp_path_info_reap(dest, pi);

// 	return dest;
// }

// static void delete_vni_type2_routes(struct bgp *bgp, struct bgpevpn *vpn)
// {
// 	struct bgp_dest *dest;

// 	/* Next, walk this VNI's MAC & IP route table and delete local type-2
// 	 * routes.
// 	 */
// 	for (dest = bgp_table_top(vpn->mac_table); dest;
// 	     dest = bgp_route_next(dest)) {
// 		dest = delete_vni_type2_route(bgp, dest);
// 		assert(dest);
// 	}

// 	for (dest = bgp_table_top(vpn->ip_table); dest;
// 	     dest = bgp_route_next(dest)) {
// 		dest = delete_vni_type2_route(bgp, dest);
// 		assert(dest);
// 	}
// }

// /*
//  * Delete all type-2 (MACIP) local routes for this VNI - from the global
//  * table as well as the per-VNI route table.
//  */
// static void delete_all_type2_routes(struct bgp *bgp, struct bgpevpn *vpn)
// {
// 	/* First, walk the global route table for this VNI's type-2 local
// 	 * routes.
// 	 * EVPN routes are a 2-level table, first get the RD table.
// 	 */
// 	delete_global_type2_routes(bgp, vpn);
// 	delete_vni_type2_routes(bgp, vpn);
// }

// /*
//  * Delete all routes in the per-VNI route table.
//  */
// static void delete_all_vni_routes(struct bgp *bgp, struct bgpevpn *vpn)
// {
// 	struct bgp_dest *dest;
// 	struct bgp_path_info *pi, *nextpi;

// 	/* Walk this VNI's MAC & IP route table and delete all routes. */
// 	for (dest = bgp_table_top(vpn->mac_table); dest;
// 	     dest = bgp_route_next(dest)) {
// 		for (pi = bgp_dest_get_bgp_path_info(dest);
// 		     (pi != NULL) && (nextpi = pi->next, 1); pi = nextpi) {
// 			bgp_evpn_remote_ip_hash_del(vpn, pi);
// 			bgp_path_info_mark_for_delete(dest, pi);
// 			dest = bgp_path_info_reap(dest, pi);

// 			assert(dest);
// 		}
// 	}

// 	for (dest = bgp_table_top(vpn->ip_table); dest;
// 	     dest = bgp_route_next(dest)) {
// 		for (pi = bgp_dest_get_bgp_path_info(dest);
// 		     (pi != NULL) && (nextpi = pi->next, 1); pi = nextpi) {
// 			bgp_path_info_mark_for_delete(dest, pi);
// 			dest = bgp_path_info_reap(dest, pi);

// 			assert(dest);
// 		}
// 	}
// }

// /* BUM traffic flood mode per-l2-vni */
// static int bgp_evpn_vni_flood_mode_get(struct bgp *bgp,
// 					struct bgpevpn *vpn)
// {
// 	if (bgp_debug_zebra(NULL))
// 		zlog_debug("VRF %s vni %u flood mode %d (global flood mode %d)",
// 			   vrf_id_to_name(vpn->bgp_vrf->vrf_id), vpn->vni, vpn->vxlan_flood_ctrl,
// 			   bgp->vxlan_flood_ctrl);

// 	/* If per-VNI flood mode is set and differs from global mode,
// 	 * use per-VNI mode.
// 	 */
// 	if (vpn->vxlan_flood_ctrl != VXLAN_FLOOD_INHERIT_GLOBAL &&
// 	    vpn->vxlan_flood_ctrl != bgp->vxlan_flood_ctrl)
// 		return vpn->vxlan_flood_ctrl;

// 	/* if flooding has been globally disabled per-vni mode is
// 	 * not relevant
// 	 */
// 	if (bgp->vxlan_flood_ctrl == VXLAN_FLOOD_DISABLED)
// 		return VXLAN_FLOOD_DISABLED;

// 	/* if mcast group ip has been specified we use a PIM-SM MDT */
// 	if (vpn->mcast_grp.s_addr != INADDR_ANY)
// 		return VXLAN_FLOOD_PIM_SM;

// 	/* default is ingress replication */
// 	return VXLAN_FLOOD_HEAD_END_REPL;
// }

// /*
//  * Update (and advertise) local routes for a VNI. Invoked upon the VNI
//  * export RT getting modified or change to tunnel IP. Note that these
//  * situations need the route in the per-VNI table as well as the global
//  * table to be updated (as attributes change).
//  */
// int update_routes_for_vni(struct bgp *bgp, struct bgpevpn *vpn)
// {
// 	int ret;
// 	struct prefix_evpn p;

// 	update_type1_routes_for_evi(bgp, vpn);

// 	/* Update and advertise the type-3 route (only one) followed by the
// 	 * locally learnt type-2 routes (MACIP) - for this VNI.
// 	 *
// 	 * RT-3 only if doing head-end replication
// 	 */
// 	if (bgp_evpn_vni_flood_mode_get(bgp, vpn)
// 				== VXLAN_FLOOD_HEAD_END_REPL) {
// 		build_evpn_type3_prefix(&p, vpn->originator_ip);
// 		ret = update_evpn_route(bgp, vpn, &p, 0, 0, NULL);
// 		if (ret)
// 			return ret;
// 	}

// 	update_all_type2_routes(bgp, vpn);
// 	return 0;
// }

// /* Update Type-2/3 Routes for L2VNI.
//  * Called by hash_iterate()
//  */
// static void update_routes_for_vni_hash(struct hash_bucket *bucket,
// 				       struct bgp *bgp)
// {
// 	struct bgpevpn *vpn;

// 	if (!bucket)
// 		return;

// 	vpn = (struct bgpevpn *)bucket->data;
// 	update_routes_for_vni(bgp, vpn);
// }

// /*
//  * Delete (and withdraw) local routes for specified VNI from the global
//  * table and per-VNI table. After this, remove all other routes from
//  * the per-VNI table. Invoked upon the VNI being deleted or EVPN
//  * (advertise-all-vni) being disabled.
//  */
// static int delete_routes_for_vni(struct bgp *bgp, struct bgpevpn *vpn)
// {
// 	int ret;
// 	struct prefix_evpn p;

// 	/* Delete and withdraw locally learnt type-2 routes (MACIP)
// 	 * followed by type-3 routes (only one) - for this VNI.
// 	 */
// 	delete_all_type2_routes(bgp, vpn);

// 	build_evpn_type3_prefix(&p, vpn->originator_ip);

// 	/*
// 	 * To handle the following scenario:
// 	 *  - Say, the new zebra announce fifo list has few vni Evpn prefixes yet
// 	 *    to be sent to zebra.
// 	 *  - At this point if we have triggers like "no advertise-all-vni" or
// 	 *    "networking restart", where a vni is going down.
// 	 *
// 	 * Perform the below
// 	 *    1) send withdraw routes to zebra immediately in case it is installed.
// 	 *    2) before we blow up the vni table, we need to walk the list and
// 	 *       pop all the dest whose za_vpn points to this vni.
// 	 */
// 	SET_FLAG(bgp->flags, BGP_FLAG_VNI_DOWN);
// 	ret = delete_evpn_route(bgp, vpn, &p);
// 	UNSET_FLAG(bgp->flags, BGP_FLAG_VNI_DOWN);
// 	if (ret)
// 		return ret;

// 	/* Delete all routes from the per-VNI table. */
// 	delete_all_vni_routes(bgp, vpn);
// 	return 0;
// }

// /*
//  * There is a flood mcast IP address change. Update the mcast-grp and
//  * remove the type-3 route if any. A new type-3 route will be generated
//  * post tunnel_ip update if the new flood mode is head-end-replication.
//  */
// static int bgp_evpn_mcast_grp_change(struct bgp *bgp, struct bgpevpn *vpn,
// 		struct in_addr mcast_grp)
// {
// 	struct prefix_evpn p;

// 	vpn->mcast_grp = mcast_grp;

// 	if (is_vni_live(vpn)) {
// 		build_evpn_type3_prefix(&p, vpn->originator_ip);
// 		delete_evpn_route(bgp, vpn, &p);
// 	}

// 	return 0;
// }

// /*
//  * If there is a tunnel endpoint IP address (VTEP-IP) change for this VNI.
//      - Deletes tip_hash entry for old VTEP-IP
//      - Adds tip_hash entry/refcount for new VTEP-IP
//      - Deletes prior type-3 route for L2VNI (if needed)
//      - Updates originator_ip
//  * Note: Route re-advertisement happens elsewhere after other processing
//  * other changes.
//  */
// static void handle_tunnel_ip_change(struct bgp *bgp_vrf, struct bgp *bgp_evpn,
// 				    struct bgpevpn *vpn,
// 				    struct in_addr originator_ip)
// {
// 	struct prefix_evpn p;
// 	struct in_addr old_vtep_ip;

// 	if (bgp_vrf) /* L3VNI */
// 		old_vtep_ip = bgp_vrf->originator_ip;
// 	else /* L2VNI */
// 		old_vtep_ip = vpn->originator_ip;

// 	/* TIP didn't change, nothing to do */
// 	if (IPV4_ADDR_SAME(&old_vtep_ip, &originator_ip))
// 		return;

// 	/* If L2VNI is not live, we only need to update the originator_ip.
// 	 * L3VNIs are updated immediately, so we can't bail out early.
// 	 */
// 	if (!bgp_vrf && !is_vni_live(vpn)) {
// 		vpn->originator_ip = originator_ip;
// 		return;
// 	}

// 	/* Update the tunnel-ip hash */
// 	bgp_tip_del(bgp_evpn, &old_vtep_ip);
// 	if (bgp_tip_add(bgp_evpn, &originator_ip))
// 		/* The originator_ip was not already present in the
// 		 * bgp martian next-hop table as a tunnel-ip, so we
// 		 * need to go back and filter routes matching the new
// 		 * martian next-hop.
// 		 */
// 		bgp_filter_evpn_routes_upon_martian_change(bgp_evpn,
// 							   BGP_MARTIAN_TUN_IP);

// 	if (!bgp_vrf) {
// 		/* Need to withdraw type-3 route as the originator IP is part
// 		 * of the key.
// 		 */
// 		build_evpn_type3_prefix(&p, vpn->originator_ip);
// 		delete_evpn_route(bgp_evpn, vpn, &p);

// 		vpn->originator_ip = originator_ip;
// 	} else
// 		bgp_vrf->originator_ip = originator_ip;

// 	return;
// }

// static struct bgp_path_info *
// bgp_create_evpn_bgp_path_info(struct bgp_path_info *parent_pi,
// 			      struct bgp_dest *dest, struct attr *attr)
// {
// 	struct attr *attr_new;
// 	struct bgp_path_info *pi;

// 	/* Add (or update) attribute to hash. */
// 	attr_new = bgp_attr_intern(attr);

// 	/* Create new route with its attribute. */
// 	pi = info_make(parent_pi->type, BGP_ROUTE_IMPORTED, 0, parent_pi->peer,
// 		       attr_new, dest);
// 	SET_FLAG(pi->flags, BGP_PATH_VALID);
// 	bgp_path_info_extra_get(pi);
// 	if (!pi->extra->vrfleak)
// 		pi->extra->vrfleak =
// 			XCALLOC(MTYPE_BGP_ROUTE_EXTRA_VRFLEAK,
// 				sizeof(struct bgp_path_info_extra_vrfleak));
// 	pi->extra->vrfleak->parent = bgp_path_info_lock(parent_pi);
// 	bgp_dest_lock_node((struct bgp_dest *)parent_pi->net);
// 	if (parent_pi->extra)
// 		pi->extra->igpmetric = parent_pi->extra->igpmetric;

// 	if (BGP_PATH_INFO_NUM_LABELS(parent_pi))
// 		pi->extra->labels = bgp_labels_intern(parent_pi->extra->labels);

// 	bgp_path_info_add(dest, pi);

// 	return pi;
// }

// /*
//  * According to draft-ietf-bess-evpn-ipvpn-interworking-13, strip the following
//  * extended communities for VRF routes imported from EVPN.
//  *
//  *   a. BGP Encapsulation extended communities.
//  *   b. Route Target extended communities.
//  *   c. All the extended communities of type EVPN.
//  */
// static bool bgp_evpn_filter_ecommunity(uint8_t *val, uint8_t size, void *arg)
// {
// 	switch (val[0]) {
// 	case ECOMMUNITY_ENCODE_AS:
// 	case ECOMMUNITY_ENCODE_IP:
// 	case ECOMMUNITY_ENCODE_AS4:
// 		if (val[1] == ECOMMUNITY_ROUTE_TARGET)
// 			return false;
// 		break;
// 	case ECOMMUNITY_ENCODE_OPAQUE:
// 		if (val[1] == ECOMMUNITY_OPAQUE_SUBTYPE_ENCAP)
// 			return false;
// 		break;
// 	case ECOMMUNITY_ENCODE_EVPN:
// 		return false;
// 	}
// 	return true;
// }

// /*
//  * Install route entry into the VRF routing table and invoke route selection.
//  */
// static int install_evpn_route_entry_in_vrf(struct bgp *bgp_vrf,
// 					   const struct prefix_evpn *evp,
// 					   struct bgp_path_info *parent_pi)
// {
// 	struct bgp_dest *dest;
// 	struct bgp_path_info *pi;
// 	struct attr attr;
// 	struct attr *attr_new;
// 	int ret = 0;
// 	struct prefix p;
// 	struct prefix *pp = &p;
// 	afi_t afi = 0;
// 	safi_t safi = 0;
// 	bool new_pi = false;
// 	bool use_l3nhg = false;
// 	bool is_l3nhg_active = false;
// 	char buf1[INET6_ADDRSTRLEN];
// 	struct bgp_route_evpn *bre;
// 	struct ecommunity *ecom;

// 	memset(pp, 0, sizeof(struct prefix));
// 	ip_prefix_from_evpn_prefix(evp, pp);

// 	if (bgp_debug_zebra(NULL))
// 		zlog_debug(
// 			"vrf %s: import evpn prefix %pFX parent %p flags 0x%x",
// 			vrf_id_to_name(bgp_vrf->vrf_id), evp, parent_pi,
// 			parent_pi->flags);

// 	if (bgp_vrf->vrf_id == VRF_UNKNOWN)
// 		return -1;

// 	/* Create (or fetch) route within the VRF. */
// 	/* NOTE: There is no RD here. */
// 	if (is_evpn_prefix_ipaddr_v4(evp)) {
// 		afi = AFI_IP;
// 		safi = SAFI_UNICAST;
// 		dest = bgp_node_get(bgp_vrf->rib[afi][safi], pp);
// 	} else if (is_evpn_prefix_ipaddr_v6(evp)) {
// 		afi = AFI_IP6;
// 		safi = SAFI_UNICAST;
// 		dest = bgp_node_get(bgp_vrf->rib[afi][safi], pp);
// 	} else
// 		return 0;

// 	/* EVPN routes currently only support a IPv4 next hop which corresponds
// 	 * to the remote VTEP. When importing into a VRF, if it is IPv6 host
// 	 * or prefix route, we have to convert the next hop to an IPv4-mapped
// 	 * address for the rest of the code to flow through. In the case of IPv4,
// 	 * make sure to set the flag for next hop attribute.
// 	 */
// 	attr = *parent_pi->attr;
// 	bre = bgp_attr_get_evpn_overlay(&attr);
// 	if (bre && bre->type == OVERLAY_INDEX_GATEWAY_IP) {
// 		/*
// 		 * If gateway IP overlay index is specified in the NLRI of
// 		 * EVPN RT-5, this gateway IP should be used as the nexthop
// 		 * for the prefix in the VRF
// 		 */
// 		if (bgp_debug_zebra(NULL)) {
// 			zlog_debug("Install gateway IP %s as nexthop for prefix %pFX in vrf %s",
// 				   inet_ntop(pp->family, &bre->gw_ip, buf1,
// 					     sizeof(buf1)),
// 				   pp, vrf_id_to_name(bgp_vrf->vrf_id));
// 		}

// 		if (afi == AFI_IP6) {
// 			memcpy(&attr.mp_nexthop_global, &bre->gw_ip.ipaddr_v6,
// 			       sizeof(struct in6_addr));
// 			attr.mp_nexthop_len = IPV6_MAX_BYTELEN;
// 		} else {
// 			attr.nexthop = bre->gw_ip.ipaddr_v4;
// 			SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP));
// 		}
// 	} else {
// 		if (afi == AFI_IP6)
// 			evpn_convert_nexthop_to_ipv6(&attr);
// 		else {
// 			attr.nexthop = attr.mp_nexthop_global_in;
// 			SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP));
// 		}
// 	}

// 	bgp_evpn_es_vrf_use_nhg(bgp_vrf, &parent_pi->attr->esi, &use_l3nhg,
// 				&is_l3nhg_active, NULL);
// 	if (use_l3nhg)
// 		SET_FLAG(attr.es_flags, ATTR_ES_L3_NHG_USE);
// 	if (is_l3nhg_active)
// 		SET_FLAG(attr.es_flags, ATTR_ES_L3_NHG_ACTIVE);

// 	ecom = ecommunity_filter(bgp_attr_get_ecommunity(&attr), bgp_evpn_filter_ecommunity, NULL);
// 	bgp_attr_set_ecommunity(&attr, ecom);

// 	/* Check if route entry is already present. */
// 	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
// 		if (pi->extra && pi->extra->vrfleak &&
// 		    (struct bgp_path_info *)pi->extra->vrfleak->parent ==
// 			    parent_pi)
// 			break;

// 	if (!pi) {
// 		pi = bgp_create_evpn_bgp_path_info(parent_pi, dest, &attr);
// 		new_pi = true;
// 	} else {
// 		if (!CHECK_FLAG(pi->flags, BGP_PATH_REMOVED) && attrhash_cmp(pi->attr, &attr)) {
// 			bgp_dest_unlock_node(dest);
// 			return 0;
// 		}
// 		/* The attribute has changed. */
// 		/* Add (or update) attribute to hash. */
// 		attr_new = bgp_attr_intern(&attr);

// 		/* Restore route, if needed. */
// 		if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
// 			bgp_path_info_restore(dest, pi);

// 		/* Mark if nexthop has changed. */
// 		if ((afi == AFI_IP
// 		     && !IPV4_ADDR_SAME(&pi->attr->nexthop, &attr_new->nexthop))
// 		    || (afi == AFI_IP6
// 			&& !IPV6_ADDR_SAME(&pi->attr->mp_nexthop_global,
// 					   &attr_new->mp_nexthop_global)))
// 			SET_FLAG(pi->flags, BGP_PATH_IGP_CHANGED);

// 		bgp_path_info_set_flag(dest, pi, BGP_PATH_ATTR_CHANGED);
// 		/* Unintern existing, set to new. */
// 		bgp_attr_unintern(&pi->attr);
// 		pi->attr = attr_new;
// 		pi->uptime = monotime(NULL);
// 	}

// 	/* Gateway IP nexthop should be resolved */
// 	if (bre && bre->type == OVERLAY_INDEX_GATEWAY_IP) {
// 		if (bgp_find_or_add_nexthop(bgp_vrf, bgp_vrf, afi, safi, pi, NULL, 0, NULL, NULL))
// 			bgp_path_info_set_flag(dest, pi, BGP_PATH_VALID);
// 		else {
// 			if (BGP_DEBUG(nht, NHT)) {
// 				inet_ntop(pp->family, &bre->gw_ip, buf1,
// 					  sizeof(buf1));
// 				zlog_debug("%s: gateway IP NH unresolved",
// 					   buf1);
// 			}
// 			bgp_path_info_unset_flag(dest, pi, BGP_PATH_VALID);
// 		}
// 	} else {
// 		/* as it is an importation, change nexthop */
// 		bgp_path_info_set_flag(dest, pi, BGP_PATH_ANNC_NH_SELF);
// 	}

// 	/* Link path to evpn nexthop */
// 	bgp_evpn_path_nh_add(bgp_vrf, pi);

// 	bgp_aggregate_increment(bgp_vrf, bgp_dest_get_prefix(dest), pi, afi,
// 				safi);

// 	/* Perform route selection and update zebra, if required. */
// 	bgp_process(bgp_vrf, dest, pi, afi, safi);

// 	/* Process for route leaking. */
// 	vpn_leak_from_vrf_update(bgp_get_default(), bgp_vrf, pi);

// 	if (bgp_debug_zebra(NULL)) {
// 		struct ipaddr nhip = {};

// 		if (pi->net->rn->p.family == AF_INET6) {
// 			SET_IPADDR_V6(&nhip);
// 			IPV6_ADDR_COPY(&nhip.ipaddr_v6, &pi->attr->mp_nexthop_global);
// 		} else {
// 			SET_IPADDR_V4(&nhip);
// 			IPV4_ADDR_COPY(&nhip.ipaddr_v4, &pi->attr->nexthop);
// 		}
// 		zlog_debug("... %s pi %s dest %p (l %d) pi %p (l %d, f 0x%x) nh %pIA",
// 			   new_pi ? "new" : "update",
// 			   bgp_vrf->name_pretty, dest,
// 			   bgp_dest_get_lock_count(dest), pi, pi->lock,
// 			   pi->flags, &nhip);
// 	}

// 	bgp_dest_unlock_node(dest);

// 	return ret;
// }

// /*
//  * Common handling for vni route tables install/selection.
//  */
// static int install_evpn_route_entry_in_vni_common(
// 	struct bgp *bgp, struct bgpevpn *vpn, const struct prefix_evpn *p,
// 	struct bgp_dest *dest, struct bgp_path_info *parent_pi)
// {
// 	struct bgp_path_info *pi;
// 	struct bgp_path_info *local_pi;
// 	struct attr *attr_new;
// 	int ret;
// 	bool old_local_es = false;
// 	bool new_local_es;

// 	/* Check if route entry is already present. */
// 	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
// 		if (pi->extra && pi->extra->vrfleak &&
// 		    (struct bgp_path_info *)pi->extra->vrfleak->parent ==
// 			    parent_pi)
// 			break;

// 	if (!pi) {
// 		/* Create an info */
// 		pi = bgp_create_evpn_bgp_path_info(parent_pi, dest,
// 						    parent_pi->attr);

// 		if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
// 			if (is_evpn_type2_dest_ipaddr_none(dest))
// 				evpn_type2_path_info_set_ip(
// 					pi, p->prefix.macip_addr.ip);
// 			else
// 				evpn_type2_path_info_set_mac(
// 					pi, p->prefix.macip_addr.mac);
// 		}

// 		new_local_es = bgp_evpn_attr_is_local_es(pi->attr);
// 	} else {
// 		/* Return early if attributes haven't changed
// 		 * and dest isn't flagged for removal.
// 		 * dest will be unlocked by either
// 		 * install_evpn_route_entry_in_vni_mac() or
// 		 * install_evpn_route_entry_in_vni_ip()
// 		 */
// 		if (!CHECK_FLAG(pi->flags, BGP_PATH_REMOVED) &&
// 		    attrhash_cmp(pi->attr, parent_pi->attr))
// 			return 0;
// 		/* The attribute has changed. */
// 		/* Add (or update) attribute to hash. */
// 		attr_new = bgp_attr_intern(parent_pi->attr);

// 		/* Restore route, if needed. */
// 		if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
// 			bgp_path_info_restore(dest, pi);

// 		/* Mark if nexthop has changed. */
// 		if (!IPV4_ADDR_SAME(&pi->attr->nexthop, &attr_new->nexthop))
// 			SET_FLAG(pi->flags, BGP_PATH_IGP_CHANGED);

// 		old_local_es = bgp_evpn_attr_is_local_es(pi->attr);
// 		new_local_es = bgp_evpn_attr_is_local_es(attr_new);
// 		/* If ESI is different or if its type has changed we
// 		 * need to reinstall the path in zebra
// 		 */
// 		if ((old_local_es != new_local_es)
// 		    || memcmp(&pi->attr->esi, &attr_new->esi,
// 			      sizeof(attr_new->esi))) {

// 			if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
// 				zlog_debug("VNI %d path %pFX chg to %s es",
// 					   vpn->vni, &pi->net->rn->p,
// 					   new_local_es ? "local" : "non-local");
// 			bgp_path_info_set_flag(dest, pi, BGP_PATH_ATTR_CHANGED);
// 		}

// 		/* Unintern existing, set to new. */
// 		bgp_attr_unintern(&pi->attr);
// 		pi->attr = attr_new;
// 		pi->uptime = monotime(NULL);
// 	}

// 	/* Add this route to remote IP hashtable */
// 	bgp_evpn_remote_ip_hash_add(vpn, pi);

// 	/* Perform route selection and update zebra, if required. */
// 	ret = evpn_route_select_install(bgp, vpn, dest, pi);

// 	/* if the best path is a local path with a non-zero ES
// 	 * sync info against the local path may need to be updated
// 	 * when a remote path is added/updated (including changes
// 	 * from sync-path to remote-path)
// 	 */
// 	local_pi = bgp_evpn_route_get_local_path(bgp, dest, 0);
// 	if (local_pi && (old_local_es || new_local_es))
// 		bgp_evpn_update_type2_route_entry(bgp, vpn, dest, local_pi,
// 						  __func__);

// 	return ret;
// }

// /*
//  * Common handling for vni route tables uninstall/selection.
//  */
// static int uninstall_evpn_route_entry_in_vni_common(
// 	struct bgp *bgp, struct bgpevpn *vpn, const struct prefix_evpn *p,
// 	struct bgp_dest *dest, struct bgp_path_info *parent_pi)
// {
// 	struct bgp_path_info *pi;
// 	struct bgp_path_info *local_pi;
// 	int ret;

// 	/* Find matching route entry. */
// 	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
// 		if (pi->extra && pi->extra->vrfleak &&
// 		    (struct bgp_path_info *)pi->extra->vrfleak->parent ==
// 			    parent_pi)
// 			break;

// 	if (!pi)
// 		return 0;

// 	bgp_evpn_remote_ip_hash_del(vpn, pi);

// 	/* Mark entry for deletion */
// 	bgp_path_info_mark_for_delete(dest, pi);

// 	/* Perform route selection and update zebra, if required. */
// 	ret = evpn_route_select_install(bgp, vpn, dest, pi);

// 	/* if the best path is a local path with a non-zero ES
// 	 * sync info against the local path may need to be updated
// 	 * when a remote path is deleted
// 	 */
// 	local_pi = bgp_evpn_route_get_local_path(bgp, dest, 0);
// 	if (local_pi && bgp_evpn_attr_is_local_es(local_pi->attr))
// 		bgp_evpn_update_type2_route_entry(bgp, vpn, dest, local_pi,
// 						  __func__);

// 	return ret;
// }

// /*
//  * Install route entry into VNI IP table and invoke route selection.
//  */
// static int install_evpn_route_entry_in_vni_ip(struct bgp *bgp,
// 					      struct bgpevpn *vpn,
// 					      const struct prefix_evpn *p,
// 					      struct bgp_path_info *parent_pi)
// {
// 	int ret;
// 	struct bgp_dest *dest;

// 	/* Ignore MAC Only Type-2 */
// 	if ((p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) &&
// 	    (is_evpn_prefix_ipaddr_none(p) == true))
// 		return 0;

// 	/* Create (or fetch) route within the VNI IP table. */
// 	dest = bgp_evpn_vni_ip_node_get(vpn->ip_table, p, parent_pi);

// 	ret = install_evpn_route_entry_in_vni_common(bgp, vpn, p, dest,
// 						     parent_pi);

// 	bgp_dest_unlock_node(dest);

// 	return ret;
// }

// /*
//  * Install route entry into VNI MAC table and invoke route selection.
//  */
// static int install_evpn_route_entry_in_vni_mac(struct bgp *bgp,
// 					       struct bgpevpn *vpn,
// 					       const struct prefix_evpn *p,
// 					       struct bgp_path_info *parent_pi)
// {
// 	int ret;
// 	struct bgp_dest *dest;

// 	/* Only type-2 routes go into this table */
// 	if (p->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
// 		return 0;

// 	/* Create (or fetch) route within the VNI MAC table. */
// 	dest = bgp_evpn_vni_mac_node_get(vpn->mac_table, p, parent_pi);

// 	ret = install_evpn_route_entry_in_vni_common(bgp, vpn, p, dest,
// 						     parent_pi);

// 	bgp_dest_unlock_node(dest);

// 	return ret;
// }

// /*
//  * Uninstall route entry from VNI IP table and invoke route selection.
//  */
// static int uninstall_evpn_route_entry_in_vni_ip(struct bgp *bgp,
// 						struct bgpevpn *vpn,
// 						const struct prefix_evpn *p,
// 						struct bgp_path_info *parent_pi)
// {
// 	int ret;
// 	struct bgp_dest *dest;

// 	/* Ignore MAC Only Type-2 */
// 	if ((p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) &&
// 	    (is_evpn_prefix_ipaddr_none(p) == true))
// 		return 0;

// 	/* Locate route within the VNI IP table. */
// 	dest = bgp_evpn_vni_ip_node_lookup(vpn->ip_table, p, parent_pi);
// 	if (!dest)
// 		return 0;

// 	ret = uninstall_evpn_route_entry_in_vni_common(bgp, vpn, p, dest,
// 						       parent_pi);

// 	bgp_dest_unlock_node(dest);

// 	return ret;
// }

// /*
//  * Uninstall route entry from VNI IP table and invoke route selection.
//  */
// static int
// uninstall_evpn_route_entry_in_vni_mac(struct bgp *bgp, struct bgpevpn *vpn,
// 				      const struct prefix_evpn *p,
// 				      struct bgp_path_info *parent_pi)
// {
// 	int ret;
// 	struct bgp_dest *dest;

// 	/* Only type-2 routes go into this table */
// 	if (p->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
// 		return 0;

// 	/* Locate route within the VNI MAC table. */
// 	dest = bgp_evpn_vni_mac_node_lookup(vpn->mac_table, p, parent_pi);
// 	if (!dest)
// 		return 0;

// 	ret = uninstall_evpn_route_entry_in_vni_common(bgp, vpn, p, dest,
// 						       parent_pi);

// 	bgp_dest_unlock_node(dest);

// 	return ret;
// }
// /*
//  * Uninstall route entry from the VRF routing table and send message
//  * to zebra, if appropriate.
//  */
// int uninstall_evpn_route_entry_in_vrf(struct bgp *bgp_vrf, const struct prefix_evpn *evp,
// 				      struct bgp_path_info *parent_pi)
// {
// 	struct bgp_dest *dest;
// 	struct bgp_path_info *pi;
// 	int ret = 0;
// 	struct prefix p;
// 	struct prefix *pp = &p;
// 	afi_t afi = 0;
// 	safi_t safi = 0;

// 	memset(pp, 0, sizeof(struct prefix));
// 	ip_prefix_from_evpn_prefix(evp, pp);

// 	if (bgp_debug_zebra(NULL))
// 		zlog_debug(
// 			"vrf %s: unimport evpn prefix %pFX parent %p flags 0x%x",
// 			vrf_id_to_name(bgp_vrf->vrf_id), evp, parent_pi,
// 			parent_pi->flags);

// 	/* Locate route within the VRF. */
// 	/* NOTE: There is no RD here. */
// 	if (is_evpn_prefix_ipaddr_v4(evp)) {
// 		afi = AFI_IP;
// 		safi = SAFI_UNICAST;
// 		dest = bgp_node_lookup(bgp_vrf->rib[afi][safi], pp);
// 	} else {
// 		afi = AFI_IP6;
// 		safi = SAFI_UNICAST;
// 		dest = bgp_node_lookup(bgp_vrf->rib[afi][safi], pp);
// 	}

// 	if (!dest)
// 		return 0;

// 	/* Find matching route entry. */
// 	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
// 		if (pi->extra && pi->extra->vrfleak &&
// 		    (struct bgp_path_info *)pi->extra->vrfleak->parent ==
// 			    parent_pi)
// 			break;

// 	if (!pi) {
// 		bgp_dest_unlock_node(dest);
// 		return 0;
// 	}

// 	if (bgp_debug_zebra(NULL)) {
// 		struct ipaddr nhip = {};

// 		if (pi->net->rn->p.family == AF_INET6) {
// 			SET_IPADDR_V6(&nhip);
// 			IPV6_ADDR_COPY(&nhip.ipaddr_v6, &pi->attr->mp_nexthop_global);
// 		} else {
// 			SET_IPADDR_V4(&nhip);
// 			IPV4_ADDR_COPY(&nhip.ipaddr_v4, &pi->attr->nexthop);
// 		}

// 		zlog_debug("... delete pi %s dest %p (l %d) pi %p (l %d, f 0x%x) nh %pIA",
// 			   bgp_vrf->name_pretty, dest,
// 			   bgp_dest_get_lock_count(dest), pi, pi->lock,
// 			   pi->flags, &nhip);
// 	}

// 	/* Process for route leaking. */
// 	vpn_leak_from_vrf_withdraw(bgp_get_default(), bgp_vrf, pi);

// 	bgp_aggregate_decrement(bgp_vrf, bgp_dest_get_prefix(dest), pi, afi,
// 				safi);

// 	/* Force deletion */
// 	SET_FLAG(dest->flags, BGP_NODE_PROCESS_CLEAR);

// 	/* Mark entry for deletion */
// 	bgp_path_info_mark_for_delete(dest, pi);

// 	/* Unlink path to evpn nexthop */
// 	bgp_evpn_path_nh_del(bgp_vrf, pi);

// 	/* Perform route selection and update zebra, if required. */
// 	bgp_process(bgp_vrf, dest, pi, afi, safi);

// 	/* Unlock route node. */
// 	bgp_dest_unlock_node(dest);

// 	return ret;
// }

// /*
//  * Install route entry into the VNI routing tables.
//  */
// static int install_evpn_route_entry(struct bgp *bgp, struct bgpevpn *vpn,
// 				    const struct prefix_evpn *p,
// 				    struct bgp_path_info *parent_pi)
// {
// 	int ret = 0;

// 	if (bgp_debug_update(parent_pi->peer, NULL, NULL, 1))
// 		zlog_debug(
// 			"%s (%u): Installing EVPN %pFX route in VNI %u IP/MAC table",
// 			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, vpn->vni);

// 	ret = install_evpn_route_entry_in_vni_mac(bgp, vpn, p, parent_pi);

// 	if (ret) {
// 		flog_err(
// 			EC_BGP_EVPN_FAIL,
// 			"%s (%u): Failed to install EVPN %pFX route in VNI %u MAC table",
// 			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, vpn->vni);

// 		return ret;
// 	}

// 	ret = install_evpn_route_entry_in_vni_ip(bgp, vpn, p, parent_pi);

// 	if (ret) {
// 		flog_err(
// 			EC_BGP_EVPN_FAIL,
// 			"%s (%u): Failed to install EVPN %pFX route in VNI %u IP table",
// 			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, vpn->vni);

// 		return ret;
// 	}

// 	return ret;
// }

// /*
//  * Uninstall route entry from the VNI routing tables.
//  */
// static int uninstall_evpn_route_entry(struct bgp *bgp, struct bgpevpn *vpn,
// 				      const struct prefix_evpn *p,
// 				      struct bgp_path_info *parent_pi)
// {
// 	int ret = 0;

// 	if (bgp_debug_update(parent_pi->peer, NULL, NULL, 1))
// 		zlog_debug(
// 			"%s (%u): Uninstalling EVPN %pFX route from VNI %u IP/MAC table",
// 			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, vpn->vni);

// 	ret = uninstall_evpn_route_entry_in_vni_ip(bgp, vpn, p, parent_pi);

// 	if (ret) {
// 		flog_err(
// 			EC_BGP_EVPN_FAIL,
// 			"%s (%u): Failed to uninstall EVPN %pFX route from VNI %u IP table",
// 			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, vpn->vni);

// 		return ret;
// 	}

// 	ret = uninstall_evpn_route_entry_in_vni_mac(bgp, vpn, p, parent_pi);

// 	if (ret) {
// 		flog_err(
// 			EC_BGP_EVPN_FAIL,
// 			"%s (%u): Failed to uninstall EVPN %pFX route from VNI %u MAC table",
// 			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, vpn->vni);

// 		return ret;
// 	}

// 	return ret;
// }

// /*
//  * Given a route entry and a VRF, see if this route entry should be
//  * imported into the VRF i.e., RTs match + Site-of-Origin check passes.
//  */
// static int is_route_matching_for_vrf(struct bgp *bgp_vrf,
// 				     struct bgp_path_info *pi)
// {
// 	struct attr *attr = pi->attr;
// 	struct ecommunity *ecom;
// 	uint32_t i;

// 	assert(attr);
// 	/* Route should have valid RT to be even considered. */
// 	if (!CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)))
// 		return 0;

// 	ecom = bgp_attr_get_ecommunity(attr);
// 	if (!ecom || !ecom->size)
// 		return 0;

// 	/* For each extended community RT, see if it matches this VNI. If any RT
// 	 * matches, we're done.
// 	 */
// 	for (i = 0; i < ecom->size; i++) {
// 		uint8_t *pnt;
// 		uint8_t type, sub_type;
// 		struct ecommunity_val *eval;
// 		struct ecommunity_val eval_tmp;
// 		struct vrf_irt_node *irt;

// 		/* Only deal with RTs */
// 		pnt = (ecom->val + (i * ecom->unit_size));
// 		eval = (struct ecommunity_val *)(ecom->val
// 						 + (i * ecom->unit_size));
// 		type = *pnt++;
// 		sub_type = *pnt++;
// 		if (sub_type != ECOMMUNITY_ROUTE_TARGET)
// 			continue;

// 		/* See if this RT matches specified VNIs import RTs */
// 		irt = lookup_vrf_import_rt(eval);
// 		if (irt)
// 			if (is_vrf_present_in_irt_vrfs(irt->vrfs, bgp_vrf))
// 				return 1;

// 		/* Also check for non-exact match. In this, we mask out the AS
// 		 * and
// 		 * only check on the local-admin sub-field. This is to
// 		 * facilitate using
// 		 * VNI as the RT for EBGP peering too.
// 		 */
// 		irt = NULL;
// 		if (type == ECOMMUNITY_ENCODE_AS
// 		    || type == ECOMMUNITY_ENCODE_AS4
// 		    || type == ECOMMUNITY_ENCODE_IP) {
// 			memcpy(&eval_tmp, eval, ecom->unit_size);
// 			mask_ecom_global_admin(&eval_tmp, eval);
// 			irt = lookup_vrf_import_rt(&eval_tmp);
// 		}
// 		if (irt)
// 			if (is_vrf_present_in_irt_vrfs(irt->vrfs, bgp_vrf))
// 				return 1;
// 	}

// 	return 0;
// }

// /*
//  * Given a route entry and a VNI, see if this route entry should be
//  * imported into the VNI i.e., RTs match.
//  */
// static int is_route_matching_for_vni(struct bgp *bgp, struct bgpevpn *vpn,
// 				     struct bgp_path_info *pi)
// {
// 	struct attr *attr = pi->attr;
// 	struct ecommunity *ecom;
// 	uint32_t i;

// 	assert(attr);
// 	/* Route should have valid RT to be even considered. */
// 	if (!CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)))
// 		return 0;

// 	ecom = bgp_attr_get_ecommunity(attr);
// 	if (!ecom || !ecom->size)
// 		return 0;

// 	/* For each extended community RT, see if it matches this VNI. If any RT
// 	 * matches, we're done.
// 	 */
// 	for (i = 0; i < ecom->size; i++) {
// 		uint8_t *pnt;
// 		uint8_t type, sub_type;
// 		struct ecommunity_val *eval;
// 		struct ecommunity_val eval_tmp;
// 		struct irt_node *irt;

// 		/* Only deal with RTs */
// 		pnt = (ecom->val + (i * ecom->unit_size));
// 		eval = (struct ecommunity_val *)(ecom->val
// 						 + (i * ecom->unit_size));
// 		type = *pnt++;
// 		sub_type = *pnt++;
// 		if (sub_type != ECOMMUNITY_ROUTE_TARGET)
// 			continue;

// 		/* See if this RT matches specified VNIs import RTs */
// 		irt = lookup_import_rt(bgp, eval);
// 		if (irt)
// 			if (is_vni_present_in_irt_vnis(irt->vnis, vpn))
// 				return 1;

// 		/* Also check for non-exact match. In this, we mask out the AS
// 		 * and
// 		 * only check on the local-admin sub-field. This is to
// 		 * facilitate using
// 		 * VNI as the RT for EBGP peering too.
// 		 */
// 		irt = NULL;
// 		if (type == ECOMMUNITY_ENCODE_AS
// 		    || type == ECOMMUNITY_ENCODE_AS4
// 		    || type == ECOMMUNITY_ENCODE_IP) {
// 			memcpy(&eval_tmp, eval, ecom->unit_size);
// 			mask_ecom_global_admin(&eval_tmp, eval);
// 			irt = lookup_import_rt(bgp, &eval_tmp);
// 		}
// 		if (irt)
// 			if (is_vni_present_in_irt_vnis(irt->vnis, vpn))
// 				return 1;
// 	}

// 	return 0;
// }

// static bool bgp_evpn_route_matches_macvrf_soo(struct bgp_path_info *pi,
// 					      const struct prefix_evpn *evp)
// {
// 	struct bgp *bgp_evpn = bgp_get_evpn();
// 	struct ecommunity *macvrf_soo;
// 	bool ret = false;

// 	if (!bgp_evpn || !bgp_evpn->evpn_info)
// 		return false;

// 	/* We only stamp the mac-vrf soo on routes from our local L2VNI.
// 	 * No need to filter additional EVPN routes that originated outside
// 	 * the MAC-VRF/L2VNI.
// 	 */
// 	if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE &&
// 	    evp->prefix.route_type != BGP_EVPN_IMET_ROUTE)
// 		return false;

// 	macvrf_soo = bgp_evpn->evpn_info->soo;
// 	ret = route_matches_soo(pi, macvrf_soo);

// 	if (ret && bgp_debug_zebra(NULL)) {
// 		char *ecom_str;

// 		ecom_str = ecommunity_ecom2str(macvrf_soo,
// 					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
// 		zlog_debug(
// 			"import of evpn prefix %pFX skipped, local mac-vrf soo %s",
// 			evp, ecom_str);
// 		ecommunity_strfree(&ecom_str);
// 	}

// 	return ret;
// }

// /* This API will scan evpn routes for checking attribute's rmac
//  * macthes with bgp instance router mac. It avoid installing
//  * route into bgp vrf table and remote rmac in bridge table.
//  */
// static int bgp_evpn_route_rmac_self_check(struct bgp *bgp_vrf,
// 					  const struct prefix_evpn *evp,
// 					  struct bgp_path_info *pi)
// {
// 	/* evpn route could have learnt prior to L3vni has come up,
// 	 * perform rmac check before installing route and
// 	 * remote router mac.
// 	 * The route will be removed from global bgp table once
// 	 * SVI comes up with MAC and stored in hash, triggers
// 	 * bgp_mac_rescan_all_evpn_tables.
// 	 */
// 	if (memcmp(&bgp_vrf->rmac, &pi->attr->rmac, ETH_ALEN) == 0) {
// 		if (bgp_debug_update(pi->peer, NULL, NULL, 1)) {
// 			char attr_str[BUFSIZ] = {0};

// 			bgp_dump_attr(pi->attr, attr_str, sizeof(attr_str));

// 			zlog_debug(
// 				"%s: bgp %u prefix %pFX with attr %s - DENIED due to self mac",
// 				__func__, bgp_vrf->vrf_id, evp, attr_str);
// 		}

// 		return 1;
// 	}

// 	return 0;
// }

// /* don't import hosts that are locally attached */
// bool bgp_evpn_skip_vrf_import_of_local_es(struct bgp *bgp_vrf, const struct prefix_evpn *evp,
// 					  struct bgp_path_info *pi, int install)
// {
// 	esi_t *esi;

// 	if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
// 		esi = bgp_evpn_attr_get_esi(pi->attr);

// 		/* Don't import routes that point to a local destination */
// 		if (bgp_evpn_attr_is_local_es(pi->attr)) {
// 			if (BGP_DEBUG(evpn_mh, EVPN_MH_RT)) {
// 				char esi_buf[ESI_STR_LEN];

// 				zlog_debug(
// 					"vrf %s of evpn prefix %pFX skipped, local es %s",
// 					install ? "import" : "unimport", evp,
// 					esi_to_str(esi, esi_buf,
// 						   sizeof(esi_buf)));
// 			}
// 			return true;
// 		}
// 	}
// 	return false;
// }

// /*
//  * Install or uninstall a mac-ip route in the provided vrf if
//  * there is a rt match
//  */
// int bgp_evpn_route_entry_install_if_vrf_match(struct bgp *bgp_vrf,
// 					      struct bgp_path_info *pi,
// 					      int install)
// {
// 	int ret = 0;
// 	const struct prefix_evpn *evp =
// 		(const struct prefix_evpn *)bgp_dest_get_prefix(pi->net);

// 	/* Consider "valid" remote routes applicable for
// 	 * this VRF.
// 	 */
// 	if (!(CHECK_FLAG(pi->flags, BGP_PATH_VALID) && pi->type == ZEBRA_ROUTE_BGP &&
// 	      pi->sub_type == BGP_ROUTE_NORMAL))
// 		return 0;

// 	if (is_route_matching_for_vrf(bgp_vrf, pi)) {
// 		if (bgp_evpn_route_rmac_self_check(bgp_vrf, evp, pi))
// 			return 0;

// 		/* don't import hosts that are locally attached */
// 		if (install && (bgp_evpn_skip_vrf_import_of_local_es(
// 					bgp_vrf, evp, pi, install) ||
// 				bgp_evpn_route_matches_macvrf_soo(pi, evp)))
// 			return 0;

// 		if (install)
// 			ret = install_evpn_route_entry_in_vrf(bgp_vrf, evp, pi);
// 		else
// 			ret = uninstall_evpn_route_entry_in_vrf(bgp_vrf, evp,
// 								pi);

// 		if (ret)
// 			flog_err(EC_BGP_EVPN_FAIL,
// 				 "Failed to %s EVPN %pFX route in VRF %s",
// 				 install ? "install" : "uninstall", evp,
// 				 vrf_id_to_name(bgp_vrf->vrf_id));
// 	}

// 	return ret;
// }

// /*
//  * Install or uninstall mac-ip routes are appropriate for this
//  * particular VRF.
//  */
// static int install_uninstall_routes_for_vrf(struct bgp *bgp_vrf, bool install)
// {
// 	afi_t afi;
// 	safi_t safi;
// 	struct bgp_dest *rd_dest, *dest;
// 	struct bgp_table *table;
// 	struct bgp_path_info *pi;
// 	int ret;
// 	struct bgp *bgp_evpn = NULL;

// 	afi = AFI_L2VPN;
// 	safi = SAFI_EVPN;
// 	bgp_evpn = bgp_get_evpn();
// 	if (!bgp_evpn)
// 		return -1;

// 	/* Walk entire global routing table and evaluate routes which could be
// 	 * imported into this VRF. Note that we need to loop through all global
// 	 * routes to determine which route matches the import rt on vrf
// 	 */
// 	for (rd_dest = bgp_table_top(bgp_evpn->rib[afi][safi]); rd_dest;
// 	     rd_dest = bgp_route_next(rd_dest)) {
// 		table = bgp_dest_get_bgp_table_info(rd_dest);
// 		if (!table)
// 			continue;

// 		for (dest = bgp_table_top(table); dest;
// 		     dest = bgp_route_next(dest)) {
// 			const struct prefix_evpn *evp =
// 				(const struct prefix_evpn *)bgp_dest_get_prefix(
// 					dest);

// 			/* if not mac-ip route skip this route */
// 			if (!(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE ||
// 			      evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE))
// 				continue;

// 			/* if not a mac+ip route skip this route */
// 			if (!(is_evpn_prefix_ipaddr_v4(evp) || is_evpn_prefix_ipaddr_v6(evp)))
// 				continue;

// 			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
// 			     pi = pi->next) {
// 				ret = bgp_evpn_route_entry_install_if_vrf_match(bgp_vrf, pi,
// 										install);
// 				if (ret) {
// 					bgp_dest_unlock_node(rd_dest);
// 					bgp_dest_unlock_node(dest);
// 					return ret;
// 				}
// 			}
// 		}
// 	}

// 	return 0;
// }

// #define BGP_PROC_L2VNI_LIMIT 10
// static int install_evpn_remote_route_per_l2vni(struct bgp *bgp, struct bgp_path_info *pi,
// 					       const struct prefix_evpn *evp)
// {
// 	int ret = 0;
// 	uint8_t vni_iter = 0;
// 	struct bgpevpn *t_vpn = NULL;
// 	struct bgpevpn *t_vpn_next = NULL;

// 	for (t_vpn = zebra_l2_vni_first(&bm->zebra_l2_vni_head);
// 	     t_vpn && vni_iter < BGP_PROC_L2VNI_LIMIT; t_vpn = t_vpn_next) {
// 		t_vpn_next = zebra_l2_vni_next(&bm->zebra_l2_vni_head, t_vpn);
// 		vni_iter++;
// 		/*
// 		 * Skip install/uninstall if the route entry is not needed to
// 		 * be imported into the VNI i.e. RTs dont match
// 		 */
// 		if (!is_route_matching_for_vni(bgp, t_vpn, pi))
// 			continue;

// 		ret = install_evpn_route_entry(bgp, t_vpn, evp, pi);

// 		if (ret) {
// 			flog_err(EC_BGP_EVPN_FAIL,
// 				 "%u: Failed to install EVPN %s route in VNI %u during BP",
// 				 bgp->vrf_id, bgp_evpn_route_type_str[evp->prefix.route_type].str,
// 				 t_vpn->vni);
// 			zebra_l2_vni_del(&bm->zebra_l2_vni_head, t_vpn);

// 			return ret;
// 		}
// 	}

// 	return 0;
// }

// /*
//  * Install or uninstall routes of specified type that are appropriate for this
//  * particular VNI.
//  */
// int install_uninstall_routes_for_vni(struct bgp *bgp, struct bgpevpn *vpn, bool install)
// {
// 	afi_t afi;
// 	safi_t safi;
// 	struct bgp_dest *rd_dest, *dest;
// 	struct bgp_table *table;
// 	struct bgp_path_info *pi;
// 	int ret = 0;
// 	uint8_t count = 0;
// 	bool walk_fifo = false;

// 	afi = AFI_L2VPN;
// 	safi = SAFI_EVPN;

// 	if (!bgp) {
// 		walk_fifo = true;
// 		bgp = bgp_get_evpn();
// 		if (!bgp) {
// 			zlog_warn("%s: No BGP EVPN instance found...", __func__);

// 			return -1;
// 		}
// 	}

// 	if (BGP_DEBUG(zebra, ZEBRA))
// 		zlog_debug("%s: Total %u L2VNI VPNs pending to be processed for remote route installation",
// 			   __func__, (uint32_t)zebra_l2_vni_count(&bm->zebra_l2_vni_head));
// 	/*
// 	 * Walk entire global routing table and evaluate routes which could be
// 	 * imported into this VPN. Note that we cannot just look at the routes
// 	 * for the VNI's RD - remote routes applicable for this VNI could have
// 	 * any RD.
// 	 * Note: EVPN routes are a 2-level table.
// 	 */
// 	for (rd_dest = bgp_table_top(bgp->rib[afi][safi]); rd_dest;
// 	     rd_dest = bgp_route_next(rd_dest)) {
// 		table = bgp_dest_get_bgp_table_info(rd_dest);
// 		if (!table)
// 			continue;

// 		for (dest = bgp_table_top(table); dest;
// 		     dest = bgp_route_next(dest)) {
// 			const struct prefix_evpn *evp =
// 				(const struct prefix_evpn *)bgp_dest_get_prefix(
// 					dest);

// 			/* Proceed only for AD, MAC_IP and IMET routes */
// 			switch (evp->prefix.route_type) {
// 			case BGP_EVPN_AD_ROUTE:
// 			case BGP_EVPN_MAC_IP_ROUTE:
// 			case BGP_EVPN_IMET_ROUTE:
// 				break;
// 			case BGP_EVPN_ES_ROUTE:
// 			case BGP_EVPN_IP_PREFIX_ROUTE:
// 				continue;
// 			}

// 			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
// 			     pi = pi->next) {
// 				/*
// 				 * Skip install/uninstall if
// 				 * - Not a valid remote routes
// 				 * - Install & evpn route matchesi macvrf SOO
// 				 */
// 				if (!(CHECK_FLAG(pi->flags, BGP_PATH_VALID) &&
// 				      pi->type == ZEBRA_ROUTE_BGP &&
// 				      pi->sub_type == BGP_ROUTE_NORMAL) ||
// 				    (install && bgp_evpn_route_matches_macvrf_soo(pi, evp)))
// 					continue;

// 				if (walk_fifo) {
// 					ret = install_evpn_remote_route_per_l2vni(bgp, pi, evp);
// 					if (ret) {
// 						bgp_dest_unlock_node(rd_dest);
// 						bgp_dest_unlock_node(dest);
// 						return ret;
// 					}
// 				} else {
// 					/*
// 					 * Skip install/uninstall if the route
// 					 * entry is not needed to be imported
// 					 * into the VNI i.e. RTs dont match
// 					 */
// 					if (!is_route_matching_for_vni(bgp, vpn, pi))
// 						continue;

// 					if (install)
// 						ret = install_evpn_route_entry(bgp, vpn, evp, pi);
// 					else
// 						ret = uninstall_evpn_route_entry(bgp, vpn, evp, pi);

// 					if (ret) {
// 						flog_err(EC_BGP_EVPN_FAIL,
// 							 "%u: Failed to %s EVPN %s route in VNI %u",
// 							 bgp->vrf_id,
// 							 install ? "install" : "uninstall",
// 							 bgp_evpn_route_type_str[evp->prefix.route_type]
// 								 .str,
// 							 vpn->vni);

// 						bgp_dest_unlock_node(rd_dest);
// 						bgp_dest_unlock_node(dest);
// 						return ret;
// 					}
// 				}
// 			}
// 		}
// 	}

// 	if (walk_fifo) {
// 		while (count < BGP_PROC_L2VNI_LIMIT) {
// 			vpn = zebra_l2_vni_pop(&bm->zebra_l2_vni_head);
// 			if (!vpn)
// 				return 0;

// 			UNSET_FLAG(vpn->flags, VNI_FLAG_ADD);
// 			count++;
// 		}
// 	}

// 	return 0;
// }

// /* Install any existing remote routes applicable for this VRF into VRF RIB. This
//  * is invoked upon l3vni-add or l3vni import rt change
//  */
// static int install_routes_for_vrf(struct bgp *bgp_vrf)
// {
// 	install_uninstall_routes_for_vrf(bgp_vrf, true);
// 	return 0;
// }

// /*
//  * Install any existing remote routes applicable for this VNI into its
//  * routing table. This is invoked when a VNI becomes "live" or its Import
//  * RT is changed.
//  */
// static int install_routes_for_vni(struct bgp *bgp, struct bgpevpn *vpn)
// {
// 	/*
// 	 * Install type-3 routes followed by type-2 routes - the ones applicable
// 	 * for this VNI.
// 	 */
// 	return install_uninstall_routes_for_vni(bgp, vpn, true);
// }

// /* uninstall routes from l3vni vrf. */
// static int uninstall_routes_for_vrf(struct bgp *bgp_vrf)
// {
// 	install_uninstall_routes_for_vrf(bgp_vrf, false);
// 	return 0;
// }

// /*
//  * Uninstall any existing remote routes for this VNI. One scenario in which
//  * this is invoked is upon an import RT change.
//  */
// static int uninstall_routes_for_vni(struct bgp *bgp, struct bgpevpn *vpn)
// {
// 	/*
// 	 * Uninstall type-2 routes followed by type-3 routes - the ones
// 	 * applicable for this VNI.
// 	 */
// 	return install_uninstall_routes_for_vni(bgp, vpn, false);
// }

// /*
//  * Install or uninstall route in matching VRFs (list).
//  */
// static int install_uninstall_route_in_vrfs(struct bgp *bgp_def, afi_t afi,
// 					   safi_t safi, struct prefix_evpn *evp,
// 					   struct bgp_path_info *pi,
// 					   struct list *vrfs, int install)
// {
// 	struct bgp *bgp_vrf;
// 	struct listnode *node, *nnode;

// 	/* Only type-2/type-5 routes go into a VRF */
// 	if (!(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE
// 	      || evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE))
// 		return 0;

// 	/* if it is type-2 route and not a mac+ip route skip this route */
// 	if ((evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
// 	    && !(is_evpn_prefix_ipaddr_v4(evp)
// 		 || is_evpn_prefix_ipaddr_v6(evp)))
// 		return 0;

// 	for (ALL_LIST_ELEMENTS(vrfs, node, nnode, bgp_vrf)) {
// 		int ret;

// 		/* don't import hosts that are locally attached */
// 		if (install && bgp_evpn_skip_vrf_import_of_local_es(
// 				       bgp_vrf, evp, pi, install))
// 			return 0;

// 		if (install)
// 			ret = install_evpn_route_entry_in_vrf(bgp_vrf, evp, pi);
// 		else
// 			ret = uninstall_evpn_route_entry_in_vrf(bgp_vrf, evp,
// 								pi);

// 		if (ret) {
// 			flog_err(EC_BGP_EVPN_FAIL,
// 				 "%u: Failed to %s prefix %pFX in VRF %s",
// 				 bgp_def->vrf_id,
// 				 install ? "install" : "uninstall", evp,
// 				 vrf_id_to_name(bgp_vrf->vrf_id));
// 			return ret;
// 		}
// 	}

// 	return 0;
// }

// /*
//  * Install or uninstall route in matching VNIs (list).
//  */
// static int install_uninstall_route_in_vnis(struct bgp *bgp, afi_t afi,
// 					   safi_t safi, struct prefix_evpn *evp,
// 					   struct bgp_path_info *pi,
// 					   struct list *vnis, int install)
// {
// 	struct bgpevpn *vpn;
// 	struct listnode *node, *nnode;

// 	for (ALL_LIST_ELEMENTS(vnis, node, nnode, vpn)) {
// 		int ret;

// 		if (!is_vni_live(vpn))
// 			continue;

// 		if (install)
// 			ret = install_evpn_route_entry(bgp, vpn, evp, pi);
// 		else
// 			ret = uninstall_evpn_route_entry(bgp, vpn, evp, pi);

// 		if (ret) {
// 			flog_err(EC_BGP_EVPN_FAIL,
// 				 "%u: Failed to %s EVPN %s route in VNI %u",
// 				 bgp->vrf_id, install ? "install" : "uninstall",
// 				 evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE
// 					 ? "MACIP"
// 					 : "IMET",
// 				 vpn->vni);
// 			return ret;
// 		}
// 	}

// 	return 0;
// }

// /*
//  * Install or uninstall route for appropriate VNIs/ESIs.
//  */
// static int bgp_evpn_install_uninstall_table(struct bgp *bgp, afi_t afi,
// 					    safi_t safi, const struct prefix *p,
// 					    struct bgp_path_info *pi,
// 					    int import, bool in_vni_rt,
// 					    bool in_vrf_rt)
// {
// 	struct prefix_evpn *evp = (struct prefix_evpn *)p;
// 	struct attr *attr = pi->attr;
// 	struct ecommunity *ecom;
// 	uint32_t i;
// 	struct prefix_evpn ad_evp;

// 	assert(attr);

// 	/* Only EVPN route-types 1-5 are supported currently */
// 	if (!(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE
// 	      || evp->prefix.route_type == BGP_EVPN_IMET_ROUTE
// 	      || evp->prefix.route_type == BGP_EVPN_ES_ROUTE
// 	      || evp->prefix.route_type == BGP_EVPN_AD_ROUTE
// 	      || evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE))
// 		return 0;

// 	/* If we don't have Route Target, nothing much to do. */
// 	if (!CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)))
// 		return 0;

// 	/* EAD prefix in the global table doesn't include the VTEP-IP so
// 	 * we need to create a different copy for the VNI
// 	 */
// 	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE)
// 		evp = evpn_type1_prefix_vni_ip_copy(&ad_evp, evp,
// 						    attr->nexthop);

// 	ecom = bgp_attr_get_ecommunity(attr);
// 	if (!ecom || !ecom->size)
// 		return -1;

// 	/* Filter routes carrying a Site-of-Origin that matches our
// 	 * local MAC-VRF SoO.
// 	 */
// 	if (import && bgp_evpn_route_matches_macvrf_soo(pi, evp))
// 		return 0;

// 	/* An EVPN route belongs to a VNI or a VRF or an ESI based on the RTs
// 	 * attached to the route */
// 	for (i = 0; i < ecom->size; i++) {
// 		uint8_t *pnt;
// 		uint8_t type, sub_type;
// 		struct ecommunity_val *eval;
// 		struct ecommunity_val eval_tmp;
// 		struct irt_node *irt;	 /* import rt for l2vni */
// 		struct vrf_irt_node *vrf_irt; /* import rt for l3vni */
// 		struct bgp_evpn_es *es;

// 		/* Only deal with RTs */
// 		pnt = (ecom->val + (i * ecom->unit_size));
// 		eval = (struct ecommunity_val *)(ecom->val
// 						 + (i * ecom->unit_size));
// 		type = *pnt++;
// 		sub_type = *pnt++;
// 		if (sub_type != ECOMMUNITY_ROUTE_TARGET)
// 			continue;

// 		/* non-local MAC-IP routes in the global route table are linked
// 		 * to the destination ES
// 		 */
// 		if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
// 			bgp_evpn_path_es_link(pi, 0,
// 					      bgp_evpn_attr_get_esi(pi->attr));

// 		/*
// 		 * AD/IMET routes (type-1/3) are imported into VNI table.
// 		 * MACIP routes (type-2) are imported into VNI and VRF tables.
// 		 * Prefix routes (type 5) are imported into VRF table.
// 		 */
// 		if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE ||
// 		    evp->prefix.route_type == BGP_EVPN_IMET_ROUTE ||
// 		    evp->prefix.route_type == BGP_EVPN_AD_ROUTE ||
// 		    evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE) {
// 			if (evp->prefix.route_type != BGP_EVPN_IP_PREFIX_ROUTE) {
// 				irt = in_vni_rt ? lookup_import_rt(bgp, eval) : NULL;
// 				if (irt)
// 					install_uninstall_route_in_vnis(bgp, afi, safi, evp, pi,
// 									irt->vnis, import);
// 			}

// 			if (evp->prefix.route_type != BGP_EVPN_AD_ROUTE &&
// 			    evp->prefix.route_type != BGP_EVPN_IMET_ROUTE) {
// 				vrf_irt = in_vrf_rt ? lookup_vrf_import_rt(eval) : NULL;
// 				if (vrf_irt)
// 					install_uninstall_route_in_vrfs(bgp, afi, safi, evp, pi,
// 									vrf_irt->vrfs, import);
// 			}

// 			/* Also check for non-exact match.
// 			 * In this, we mask out the AS and
// 			 * only check on the local-admin sub-field.
// 			 * This is to facilitate using
// 			 * VNI as the RT for EBGP peering too.
// 			 */
// 			irt = NULL;
// 			vrf_irt = NULL;
// 			if (type == ECOMMUNITY_ENCODE_AS
// 			    || type == ECOMMUNITY_ENCODE_AS4
// 			    || type == ECOMMUNITY_ENCODE_IP) {
// 				memcpy(&eval_tmp, eval, ecom->unit_size);
// 				mask_ecom_global_admin(&eval_tmp, eval);
// 				if (in_vni_rt)
// 					irt = lookup_import_rt(bgp, &eval_tmp);
// 				if (in_vrf_rt)
// 					vrf_irt =
// 						lookup_vrf_import_rt(&eval_tmp);
// 			}

// 			if (irt)
// 				install_uninstall_route_in_vnis(
// 					bgp, afi, safi, evp, pi, irt->vnis,
// 					import);
// 			if (vrf_irt)
// 				install_uninstall_route_in_vrfs(
// 					bgp, afi, safi, evp, pi, vrf_irt->vrfs,
// 					import);
// 		}

// 		/* es route is imported into the es table */
// 		if (evp->prefix.route_type == BGP_EVPN_ES_ROUTE) {

// 			/* we will match based on the entire esi to avoid
// 			 * import of an es route for esi2 into esi1
// 			 */
// 			es = bgp_evpn_es_find(&evp->prefix.es_addr.esi);
// 			if (es && bgp_evpn_is_es_local(es))
// 				bgp_evpn_es_route_install_uninstall(
// 					bgp, es, afi, safi, evp, pi, import);
// 		}
// 	}

// 	return 0;
// }

// /*
//  * Install or uninstall route for appropriate VNIs/ESIs.
//  */
// static int install_uninstall_evpn_route(struct bgp *bgp, afi_t afi, safi_t safi,
// 					const struct prefix *p,
// 					struct bgp_path_info *pi, int import)
// {
// 	return bgp_evpn_install_uninstall_table(bgp, afi, safi, p, pi, import,
// 						true, true);
// }

// void bgp_evpn_import_type2_route(struct bgp_path_info *pi, int import)
// {
// 	struct bgp *bgp_evpn;

// 	bgp_evpn = bgp_get_evpn();
// 	if (!bgp_evpn)
// 		return;

// 	install_uninstall_evpn_route(bgp_evpn, AFI_L2VPN, SAFI_EVPN,
// 				     &pi->net->rn->p, pi, import);
// }

// /*
//  * delete and withdraw all ipv4 and ipv6 routes in the vrf table as type-5
//  * routes
//  */
// static void delete_withdraw_vrf_routes(struct bgp *bgp_vrf)
// {
// 	/* Delete ipv4 default route and withdraw from peers */
// 	if (evpn_default_originate_set(bgp_vrf, AFI_IP, SAFI_UNICAST))
// 		bgp_evpn_install_uninstall_default_route(bgp_vrf, AFI_IP,
// 							 SAFI_UNICAST, false);

// 	/* delete all ipv4 routes and withdraw from peers */
// 	if (advertise_type5_routes_bestpath(bgp_vrf, AFI_IP) ||
// 	    advertise_type5_routes_multipath(bgp_vrf, AFI_IP))
// 		bgp_evpn_withdraw_type5_routes(bgp_vrf, AFI_IP, SAFI_UNICAST);

// 	/* Delete ipv6 default route and withdraw from peers */
// 	if (evpn_default_originate_set(bgp_vrf, AFI_IP6, SAFI_UNICAST))
// 		bgp_evpn_install_uninstall_default_route(bgp_vrf, AFI_IP6,
// 							 SAFI_UNICAST, false);

// 	/* delete all ipv6 routes and withdraw from peers */
// 	if (advertise_type5_routes_bestpath(bgp_vrf, AFI_IP6) ||
// 	    advertise_type5_routes_multipath(bgp_vrf, AFI_IP6))
// 		bgp_evpn_withdraw_type5_routes(bgp_vrf, AFI_IP6, SAFI_UNICAST);
// }

// /*
//  * update and advertise all ipv4 and ipv6 routes in thr vrf table as type-5
//  * routes
//  */
// void update_advertise_vrf_routes(struct bgp *bgp_vrf)
// {
// 	struct bgp *bgp_evpn = NULL; /* EVPN bgp instance */

// 	bgp_evpn = bgp_get_evpn();
// 	if (!bgp_evpn)
// 		return;

// 	if (!is_l3vni_live(bgp_vrf))
// 		return; /* Nothing to do if no l3vni */

// 	/* update all ipv4 routes */
// 	if (advertise_type5_routes_bestpath(bgp_vrf, AFI_IP) ||
// 	    advertise_type5_routes_multipath(bgp_vrf, AFI_IP))
// 		bgp_evpn_advertise_type5_routes(bgp_vrf, AFI_IP, SAFI_UNICAST);

// 	/* update ipv4 default route and withdraw from peers */
// 	if (evpn_default_originate_set(bgp_vrf, AFI_IP, SAFI_UNICAST))
// 		bgp_evpn_install_uninstall_default_route(bgp_vrf, AFI_IP,
// 							 SAFI_UNICAST, true);

// 	/* update all ipv6 routes */
// 	if (advertise_type5_routes_bestpath(bgp_vrf, AFI_IP6) ||
// 	    advertise_type5_routes_multipath(bgp_vrf, AFI_IP6))
// 		bgp_evpn_advertise_type5_routes(bgp_vrf, AFI_IP6, SAFI_UNICAST);

// 	/* update ipv6 default route and withdraw from peers */
// 	if (evpn_default_originate_set(bgp_vrf, AFI_IP6, SAFI_UNICAST))
// 		bgp_evpn_install_uninstall_default_route(bgp_vrf, AFI_IP6,
// 							 SAFI_UNICAST, true);

// }

// /*
//  * update and advertise local routes for a VRF as type-5 routes.
//  * This is invoked upon RD change for a VRF. Note taht the processing is only
//  * done in the global route table using the routes which already exist in the
//  * VRF routing table
//  */
// static void update_router_id_vrf(struct bgp *bgp_vrf)
// {
// 	/* skip if the RD is configured */
// 	if (is_vrf_rd_configured(bgp_vrf))
// 		return;

// 	/* derive the RD for the VRF based on new router-id */
// 	bgp_evpn_derive_auto_rd_for_vrf(bgp_vrf);

// 	/* update advertise ipv4|ipv6 routes as type-5 routes */
// 	update_advertise_vrf_routes(bgp_vrf);
// }

// /*
//  * Delete and withdraw all type-5 routes  for the RD corresponding to VRF.
//  * This is invoked upon VRF RD change. The processing is done only from global
//  * table.
//  */
// static void withdraw_router_id_vrf(struct bgp *bgp_vrf)
// {
// 	/* skip if the RD is configured */
// 	if (is_vrf_rd_configured(bgp_vrf))
// 		return;

// 	/* delete/withdraw ipv4|ipv6 routes as type-5 routes */
// 	delete_withdraw_vrf_routes(bgp_vrf);
// }

// static void update_advertise_vni_route(struct bgp *bgp, struct bgpevpn *vpn,
// 				       struct bgp_dest *dest)
// {
// 	struct bgp_dest *global_dest;
// 	struct bgp_path_info *pi, *global_pi;
// 	struct attr *attr;
// 	afi_t afi = AFI_L2VPN;
// 	safi_t safi = SAFI_EVPN;

// 	struct prefix_evpn tmp_evp;
// 	const struct prefix_evpn *evp =
// 		(const struct prefix_evpn *)bgp_dest_get_prefix(dest);

// 	/*
// 	 * We have already processed type-3 routes.
// 	 * Process only type-1 and type-2 routes here.
// 	 */
// 	if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE &&
// 	    evp->prefix.route_type != BGP_EVPN_AD_ROUTE)
// 		return;

// 	pi = bgp_evpn_route_get_local_path(bgp, dest, 0);
// 	if (!pi)
// 		return;

// 	/*
// 	 * VNI table MAC-IP prefixes don't have MAC so make sure it's
// 	 * set from path info here.
// 	 */
// 	if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
// 		if (is_evpn_prefix_ipaddr_none(evp)) {
// 			/* VNI MAC -> Global */
// 			evpn_type2_prefix_global_copy(
// 				&tmp_evp, evp, NULL /* mac */,
// 				evpn_type2_path_info_get_ip(pi));
// 		} else {
// 			/* VNI IP -> Global */
// 			evpn_type2_prefix_global_copy(
// 				&tmp_evp, evp, evpn_type2_path_info_get_mac(pi),
// 				NULL /* ip */);
// 		}
// 	} else {
// 		memcpy(&tmp_evp, evp, sizeof(tmp_evp));
// 	}

// 	/* Create route in global routing table using this route entry's
// 	 * attribute.
// 	 */
// 	attr = pi->attr;
// 	global_dest = bgp_evpn_global_node_get(bgp->rib[afi][safi], afi, safi,
// 					       &tmp_evp, &vpn->prd, NULL);
// 	assert(global_dest);

// 	if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
// 		/* Type-2 route */
// 		update_evpn_route_entry(
// 			bgp, vpn, afi, safi, global_dest, attr, NULL /* mac */,
// 			NULL /* ip */, 1, &global_pi, 0,
// 			mac_mobility_seqnum(attr), false /* setup_sync */,
// 			NULL /* old_is_sync */);
// 	} else {
// 		/* Type-1 route */
// 		struct bgp_evpn_es *es;
// 		int route_changed = 0;

// 		es = bgp_evpn_es_find(&evp->prefix.ead_addr.esi);
// 		bgp_evpn_mh_route_update(bgp, es, vpn, afi, safi, global_dest,
// 					 attr, &global_pi, &route_changed);
// 	}

// 	/* Schedule for processing and unlock node. */
// 	bgp_process(bgp, global_dest, global_pi, afi, safi);
// 	bgp_dest_unlock_node(global_dest);
// }

// /*
//  * Update and advertise local routes for a VNI. Invoked upon router-id/RD
//  * change. Note that the processing is done only on the global route table
//  * using routes that already exist in the per-VNI table.
//  */
// static void update_advertise_vni_routes(struct bgp *bgp, struct bgpevpn *vpn)
// {
// 	struct prefix_evpn p;
// 	struct bgp_dest *dest, *global_dest;
// 	struct bgp_path_info *pi;
// 	struct attr *attr;
// 	afi_t afi = AFI_L2VPN;
// 	safi_t safi = SAFI_EVPN;

// 	/* Locate type-3 route for VNI in the per-VNI table and use its
// 	 * attributes to create and advertise the type-3 route for this VNI
// 	 * in the global table.
// 	 *
// 	 * RT-3 only if doing head-end replication
// 	 */
// 	if (bgp_evpn_vni_flood_mode_get(bgp, vpn)
// 				== VXLAN_FLOOD_HEAD_END_REPL) {
// 		build_evpn_type3_prefix(&p, vpn->originator_ip);
// 		dest = bgp_evpn_vni_node_lookup(vpn, &p, NULL);
// 		if (!dest) /* unexpected */
// 			return;
// 		pi = bgp_evpn_route_get_local_path(bgp, dest, 0);
// 		if (!pi) {
// 			bgp_dest_unlock_node(dest);
// 			return;
// 		}

// 		attr = pi->attr;

// 		global_dest = bgp_evpn_global_node_get(
// 			bgp->rib[afi][safi], afi, safi, &p, &vpn->prd, NULL);
// 		update_evpn_route_entry(
// 			bgp, vpn, afi, safi, global_dest, attr, NULL /* mac */,
// 			NULL /* ip */, 1, &pi, 0, mac_mobility_seqnum(attr),
// 			false /* setup_sync */, NULL /* old_is_sync */);

// 		/* Schedule for processing and unlock node. */
// 		bgp_process(bgp, global_dest, pi, afi, safi);
// 		bgp_dest_unlock_node(global_dest);
// 	}

// 	/* Now, walk this VNI's MAC & IP route table and use the route and its
// 	 * attribute to create and schedule route in global table.
// 	 */
// 	for (dest = bgp_table_top(vpn->mac_table); dest;
// 	     dest = bgp_route_next(dest))
// 		update_advertise_vni_route(bgp, vpn, dest);

// 	for (dest = bgp_table_top(vpn->ip_table); dest;
// 	     dest = bgp_route_next(dest))
// 		update_advertise_vni_route(bgp, vpn, dest);
// }

// /*
//  * Delete (and withdraw) local routes for a VNI - only from the global
//  * table. Invoked upon router-id change.
//  */
// static int delete_withdraw_vni_routes(struct bgp *bgp, struct bgpevpn *vpn)
// {
// 	struct prefix_evpn p;
// 	struct bgp_dest *global_dest;
// 	struct bgp_path_info *pi;
// 	afi_t afi = AFI_L2VPN;
// 	safi_t safi = SAFI_EVPN;

// 	/* Delete and withdraw locally learnt type-2 routes (MACIP)
// 	 * for this VNI - from the global table.
// 	 */
// 	delete_global_type2_routes(bgp, vpn);

// 	/* Remove type-3 route for this VNI from global table. */
// 	build_evpn_type3_prefix(&p, vpn->originator_ip);
// 	global_dest = bgp_evpn_global_node_lookup(bgp->rib[afi][safi], safi, &p,
// 						  &vpn->prd, NULL);
// 	if (global_dest) {
// 		/* Delete route entry in the global EVPN table. */
// 		pi = delete_evpn_route_entry(bgp, afi, safi, global_dest, 0);

// 		/* Schedule for processing - withdraws to peers happen from
// 		 * this table.
// 		 */
// 		if (pi)
// 			bgp_process(bgp, global_dest, pi, afi, safi);
// 		bgp_dest_unlock_node(global_dest);
// 	}


// 	delete_global_ead_evi_routes(bgp, vpn);
// 	return 0;
// }

// /*
//  * Handle router-id change. Update and advertise local routes corresponding
//  * to this VNI from peers. Note that this is invoked after updating the
//  * router-id. The routes in the per-VNI table are used to create routes in
//  * the global table and schedule them.
//  */
// static void update_router_id_vni(struct hash_bucket *bucket, struct bgp *bgp)
// {
// 	struct bgpevpn *vpn = (struct bgpevpn *)bucket->data;

// 	/* Skip VNIs with configured RD. */
// 	if (is_rd_configured(vpn))
// 		return;

// 	bgp_evpn_derive_auto_rd(bgp, vpn);
// 	update_advertise_vni_routes(bgp, vpn);
// }

// /*
//  * Handle router-id change. Delete and withdraw local routes corresponding
//  * to this VNI from peers. Note that this is invoked prior to updating
//  * the router-id and is done only on the global route table, the routes
//  * are needed in the per-VNI table to re-advertise with new router id.
//  */
// static void withdraw_router_id_vni(struct hash_bucket *bucket, struct bgp *bgp)
// {
// 	struct bgpevpn *vpn = (struct bgpevpn *)bucket->data;

// 	/* Skip VNIs with configured RD. */
// 	if (is_rd_configured(vpn))
// 		return;

// 	delete_withdraw_vni_routes(bgp, vpn);
// }

// static void advertise_withdraw_type3(struct hash_bucket *bucket, void *data)
// {
// 	struct bgpevpn *vpn = bucket->data;
// 	struct bgp *bgp = data;
// 	struct prefix_evpn p;
// 	int flood_control;

// 	if (!vpn || !is_vni_live(vpn))
// 		return;

// 	zlog_info("L2VPN EVPN BUM handling for VNI %u is %s", vpn->vni,
// 		  vxlan_flood_control_str(vpn->vxlan_flood_ctrl));

// 	bgp_zebra_vxlan_flood_control(bgp, vpn);

// 	flood_control = bgp_evpn_vni_flood_mode_get(bgp, vpn);

// 	/* Create RT-3 for a VNI and schedule for processing and advertisement.
// 	 * This is invoked upon flooding mode changing to head-end replication.
// 	 */
// 	if (flood_control == VXLAN_FLOOD_HEAD_END_REPL) {
// 		build_evpn_type3_prefix(&p, vpn->originator_ip);
// 		if (update_evpn_route(bgp, vpn, &p, 0, 0, NULL))
// 			flog_err(EC_BGP_EVPN_ROUTE_CREATE,
// 				 "Type3 route creation failure for VNI %u", vpn->vni);
// 	} else if (flood_control == VXLAN_FLOOD_DISABLED) {
// 		/* Delete RT-3 for a VNI and schedule for processing and withdrawal.
// 		 * This is invoked upon flooding mode changing to drop BUM packets.
// 		 */
// 		build_evpn_type3_prefix(&p, vpn->originator_ip);
// 		delete_evpn_route(bgp, vpn, &p);
// 	}
// }

// /*
//  * Process received MPTE route
//  */
static int mpte_process_js_route(struct peer *peer, afi_t afi, safi_t safi,
			       struct attr *attr, uint8_t *pfx, int psize)
{
	struct prefix_mpte p = {};
	uint32_t dag_id;
	uint32_t ver_num;
	uint16_t tunnel_type;
	uint32_t junction_bw;

	if (psize != 16) {
		flog_err(EC_BGP_MPTE_ROUTE_INVALID,
			 "%u:%s - Rx MPTE Type-1 NLRI with invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	struct stream *pkt = stream_new(psize);
	stream_put(pkt, pfx, psize);

	/* Make MPTE prefix. */
	p.family = AF_MPTE;
	// !!TODO:
	p.prefixlen = psize * NBBY;
	p.prefix.route_type = BGP_MPTE_JUNCTION_STATE;

	/* Copy MC Address */
	STREAM_GET(&p.prefix.js_addr.mc_addr, pkt, 4);

	/* Get MPTE ID */
	STREAM_GET(&dag_id, pkt, 4);
	p.prefix.js_addr.dag_id = ntohl(dag_id);

#if 0
	/* Get MPTE Version */
	STREAM_GET(&ver_num, pkt, 4);
	p.prefix.js_addr.version = ntohl(ver_num);

	/* Get Tunnel Type */
	STREAM_GET(&tunnel_type, pkt, 2);
	p.prefix.js_addr.tunnel_type = ntohs(tunnel_type);
#endif
	/* Get Junction Node Address */
	STREAM_GET(&p.prefix.js_addr.node_addr, pkt, 4);

	/* Get Originating Node Address */
	STREAM_GET(&p.prefix.js_addr.origin_addr, pkt, 4);

	/* Get Junction BW
	STREAM_GET(&junction_bw, pkt, 4);
	p.prefix.js_addr.junction_bw = ntohl(junction_bw);
 */
	/* Process the route. */
	if (attr)
		bgp_update(peer, (struct prefix *)&p, 0, attr, afi,
			   safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL,
			   NULL, 0, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, 0, afi, safi,
			     ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, NULL,
			     0);

	stream_free(pkt);
	stream_failure:
	return 0;
}


int bgp_nlri_parse_mpte(struct peer *peer, struct attr *attr,
			struct bgp_nlri *packet, bool withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	afi_t afi;
	safi_t safi;
	int psize = 0;
	uint8_t rtype;
	struct prefix p;

	/* Start processing the NLRI - there may be multiple in the MP_REACH */
	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;

	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(p));

		/* All MPTE NLRI types start with type and length. */
		if (pnt + 2 > lim)
			return BGP_NLRI_PARSE_ERROR_MPTE_MISSING_TYPE;

		rtype = *pnt++;
		psize = *pnt++;

		/* When packet overflow occur return immediately. */
		if (pnt + psize > lim)
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

		switch (rtype) {
		case BGP_MPTE_JUNCTION_STATE:
			if (mpte_process_js_route(peer, afi, safi,
						withdraw ? NULL : attr, pnt,
						psize)) {
				flog_err(
					EC_BGP_MPTE_FAIL,
					"%u:%s - Error in processing MPTE junction state NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_MPTE_TYPE1_SIZE;
			}
			break;
		default:
			break;
		}
	}

	/* Packet length consistency check. */
	if (pnt != lim)
		return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;

	return BGP_NLRI_PARSE_OK;
}

