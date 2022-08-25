// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package worldcidrs

import (
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/worldcidrsmap"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "worldcidrs")
)

type k8sCacheSyncedChecker interface {
	K8sCacheIsSynced() bool
}

// cidrSetID includes CIDR set name and namespace.
type cidrSetID = types.NamespacedName

// CIDRSet is the internal representation of CiliumWorldCIDRSets.
type CIDRSet struct {
	// id is the parsed config name and namespace
	id cidrSetID

	cidrs []*net.IPNet
}

// The world CIDRs manager stores the internal data tracking the world CIDRs.
// It also hooks up all the callbacks to update the BPF map accordingly.
type Manager struct {
	lock.Mutex

	// k8sCacheSyncedChecker is used to check if the agent has synced its
	// cache with the k8s API server
	k8sCacheSyncedChecker k8sCacheSyncedChecker

	// cidrSets stores CIDR sets indexed by their ID
	cidrSets map[cidrSetID]*CIDRSet
}

// NewWorldCIDRsManager returns a new world CIDRs manager.
func NewWorldCIDRsManager(k8sCacheSyncedChecker k8sCacheSyncedChecker) *Manager {
	manager := &Manager{
		k8sCacheSyncedChecker: k8sCacheSyncedChecker,
		cidrSets:              make(map[cidrSetID]*CIDRSet),
	}

	manager.runReconciliationAfterK8sSync()

	return manager
}

// runReconciliationAfterK8sSync spawns a goroutine that waits for the agent to
// sync with k8s and then runs the first reconciliation.
func (manager *Manager) runReconciliationAfterK8sSync() {
	go func() {
		for {
			if manager.k8sCacheSyncedChecker.K8sCacheIsSynced() {
				break
			}

			time.Sleep(1 * time.Second)
		}

		manager.Lock()
		manager.reconcile()
		manager.Unlock()
	}()
}

// Event handlers

// OnAddWorldCIDRSet parses the given CIDR set and updates internal state
// with the CIDRs.
func (manager *Manager) OnAddWorldCIDRSet(cidrSet CIDRSet) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.CiliumWorldCIDRSetName, cidrSet.id.Name)

	if _, ok := manager.cidrSets[cidrSet.id]; !ok {
		logger.Info("Added CiliumWorldCIDRSet")
	} else {
		logger.Info("Updated CiliumWorldCIDRSet")
	}

	manager.cidrSets[cidrSet.id] = &cidrSet

	manager.reconcile()
}

// OnDeleteWorldCIDRSet deletes the internal state associated with the given
// world CIDR set, including BPF map entries.
func (manager *Manager) OnDeleteWorldCIDRSet(id cidrSetID) {
	manager.Lock()
	defer manager.Unlock()

	logger := log.WithField(logfields.CiliumWorldCIDRSetName, id.Name)

	if manager.cidrSets[id] == nil {
		logger.Warn("Can't delete CiliumWorldCIDRSet: set not found")
		return
	}

	delete(manager.cidrSets, id)
	logger.Info("Deleted CiliumWorldCIDRSet")

	manager.reconcile()
}

func (manager *Manager) addMissingCIDRs() {
	worldCIDRs := map[worldcidrsmap.WorldCIDRKey4]worldcidrsmap.WorldCIDRVal{}
	worldcidrsmap.WorldCIDRsMap.IterateWithCallback(
		func(key *worldcidrsmap.WorldCIDRKey4, val *worldcidrsmap.WorldCIDRVal) {
			worldCIDRs[*key] = *val
		})

	addCIDR := func(cidr *net.IPNet) {
		worldCIDRKey := worldcidrsmap.NewWorldCIDRKey4(cidr)
		_, cidrPresent := worldCIDRs[worldCIDRKey]

		if cidrPresent {
			return
		}

		logger := log.WithFields(logrus.Fields{
			logfields.CIDR: cidr,
		})

		if err := worldcidrsmap.WorldCIDRsMap.Add(cidr); err != nil {
			logger.WithError(err).Error("Error adding world CIDR")
		} else {
			logger.Info("World CIDR added")
		}
	}

	for _, cidrSet := range manager.cidrSets {
		for _, cidr := range cidrSet.cidrs {
			addCIDR(cidr)
		}
	}
}

// removeUnusedCIDRs is responsible for removing any entry in the world CIDR
// BPF map which is not baked by an actual k8s CiliumWorldCIDRSet.
func (manager *Manager) removeUnusedCIDRs() {
	worldCIDRs := map[worldcidrsmap.WorldCIDRKey4]worldcidrsmap.WorldCIDRVal{}
	worldcidrsmap.WorldCIDRsMap.IterateWithCallback(
		func(key *worldcidrsmap.WorldCIDRKey4, val *worldcidrsmap.WorldCIDRVal) {
			worldCIDRs[*key] = *val
		})

nextCIDR:
	for worldCIDR := range worldCIDRs {
		for _, cidrSet := range manager.cidrSets {
			for _, cidr := range cidrSet.cidrs {
				if worldCIDR.Matches(cidr) {
					continue nextCIDR
				}
			}
		}

		logger := log.WithFields(logrus.Fields{
			logfields.CIDR: worldCIDR.GetCIDR(),
		})

		if err := worldcidrsmap.WorldCIDRsMap.Delete(worldCIDR.GetCIDR()); err != nil {
			logger.WithError(err).Error("Error removing world CIDR")
		} else {
			logger.Info("World CIDR removed")
		}
	}
}

// reconcile is responsible for reconciling the state of the manager (i.e. the
// desired state) with the actual state of the node (world CIDR map entries).
//
// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (manager *Manager) reconcile() {
	if !manager.k8sCacheSyncedChecker.K8sCacheIsSynced() {
		return
	}

	// The order of the next 2 function calls matters, as by first adding
	// missing CIDRs and only then removing obsolete ones we make sure there
	// will be no connectivity disruption.
	manager.addMissingCIDRs()
	manager.removeUnusedCIDRs()
}
