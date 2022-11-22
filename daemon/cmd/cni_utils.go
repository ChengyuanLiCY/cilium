package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/containernetworking/cni/libcni"
)

// Get the default CNI configuration under some directory
func getDefaultCNINetworkList(confDir string) (string, []byte, error) {
	files, err := libcni.ConfFiles(confDir, []string{".conf", ".conflist"})
	switch {
	case err != nil:
		return "", nil, err
	case len(files) == 0:
		return "", nil, fmt.Errorf("no networks found in %s", confDir)
	}

	sort.Strings(files)
	for _, confFile := range files {
		confList, err := getCNINetworkListFromFile(confFile)
		if err != nil {
			continue
		}
		return confFile, confList, nil
	}

	return "", nil, fmt.Errorf("no valid networks found in %s", confDir)
}

// Get the CNI network list from the file.
// If the file is suffixed with .conflist, read the contents directly
// If the file is suffixed with .conf, convert the Conf to ConfList
func getCNINetworkListFromFile(name string) ([]byte, error) {
	var confList *libcni.NetworkConfigList
	var err error
	if strings.HasSuffix(name, ".conflist") {
		confList, err = libcni.ConfListFromFile(name)
		if err != nil {
			log.Warnf("Error loading CNI config list file %s: %v", name, err)
			return nil, err
		}
	} else {
		conf, err := libcni.ConfFromFile(name)
		if err != nil {
			log.Warnf("Error loading CNI config file %s: %v", name, err)
			return nil, err
		}
		// Ensure the config has a "type" so we know what plugin to run.
		// Also catches the case where somebody put a conflist into a conf file.
		if conf.Network.Type == "" {
			log.Warnf("Error loading CNI config file %s: no 'type'; perhaps this is a .conflist?", name)
			return nil, err
		}

		confList, err = libcni.ConfListFromConf(conf)
		if err != nil {
			log.Warnf("Error converting CNI config file %s to list: %v", name, err)
			return nil, err
		}
	}
	if len(confList.Plugins) == 0 {
		log.Warnf("CNI config list %s has no networks, skipping", confList.Name)
		return nil, err
	}

	return confList.Bytes, nil
}

// Append the new CNI configuration into the original CNI configuration
func insertConfList(cniChainMode string, original []byte, inserted []byte) ([]byte, error) {
	var originalMap map[string]interface{}
	err := json.Unmarshal(original, &originalMap)
	if err != nil {
		return nil, fmt.Errorf("error loading existing CNI config (JSON error): %v", err)
	}

	var insertedMap map[string]interface{}
	err = json.Unmarshal(inserted, &insertedMap)
	if err != nil {
		return nil, fmt.Errorf("error loading inserted CNI config (JSON error): %v", err)
	}

	newMap := make(map[string]interface{}, 0)
	newMap["name"] = cniChainMode

	if insertedCniVersion, ok := insertedMap["cniVersion"]; ok {
		newMap["cniVersion"] = insertedCniVersion
	} else {
		if existingCniVersion, ok := originalMap["cniVersion"]; ok {
			newMap["cniVersion"] = existingCniVersion
		} else {
			newMap["cniVersion"] = "0.3.1"
		}
	}

	delete(insertedMap, "cniVersion")
	delete(originalMap, "cniVersion")

	originalPlugins, err := getPluginsFromCNIConfigMap(originalMap)
	if err != nil {
		return nil, fmt.Errorf("error loading CNI config plugin: %v", err)
	}

	insertedPlugins, err := getPluginsFromCNIConfigMap(insertedMap)
	if err != nil {
		return nil, fmt.Errorf("error loading CNI config plugin: %v", err)
	}

	for _, insertedPlugin := range insertedPlugins {
		iPlugin, err := getPlugin(insertedPlugin)
		if err != nil {
			return nil, fmt.Errorf("error loading CNI config plugin: %v", err)
		}
		for i, originalPlugin := range originalPlugins {
			oPlugin, err := getPlugin(originalPlugin)
			delete(originalPlugins[i].(map[string]interface{}), "cniVersion")
			if err != nil {
				return nil, fmt.Errorf("error loading CNI config plugin: %v", err)
			}
			if oPlugin["type"] == iPlugin["type"] {
				originalPlugins = append(originalPlugins[:i], originalPlugins[i+1:]...)
				break
			}
		}
		delete(iPlugin, "cniVersion")
		originalPlugins = append(originalPlugins, iPlugin)
	}
	newMap["plugins"] = originalPlugins
	return marshalCNIConfig(newMap)
}

// Get the plugins form CNI config map
func getPluginsFromCNIConfigMap(cniConfigMap map[string]interface{}) ([]interface{}, error) {
	var plugins []interface{}
	var err error
	if _, ok := cniConfigMap["type"]; ok {
		// Assume it is a regular network conf file
		plugins = []interface{}{cniConfigMap}
	} else {
		plugins, err = getPlugins(cniConfigMap)
		if err != nil {
			return nil, fmt.Errorf("error loading CNI config plugins from the existing file: %v", err)
		}
	}
	return plugins, nil
}

// Given the raw plugin interface, return the plugin asserted as a map[string]interface{}
func getPlugin(rawPlugin interface{}) (map[string]interface{}, error) {
	plugin, ok := rawPlugin.(map[string]interface{})
	if !ok {
		err := fmt.Errorf("error reading plugin from CNI config plugin list")
		return plugin, err
	}
	return plugin, nil
}

// Given an unmarshalled CNI config JSON map, return the plugin list asserted as a []interface{}
func getPlugins(cniConfigMap map[string]interface{}) ([]interface{}, error) {
	plugins, ok := cniConfigMap["plugins"].([]interface{})
	if !ok {
		err := fmt.Errorf("error reading plugin list from CNI config")
		return plugins, err
	}
	return plugins, nil
}

// Marshal the CNI config map and append a new line
func marshalCNIConfigFromBytes(cniConfigBytes []byte) ([]byte, error) {
	var cniMap map[string]interface{}
	err := json.Unmarshal(cniConfigBytes, &cniMap)
	if err != nil {
		return nil, err
	}
	return marshalCNIConfig(cniMap)
}

// Marshal the CNI config map and append a new line
func marshalCNIConfig(cniConfigMap map[string]interface{}) ([]byte, error) {
	cniConfig, err := json.MarshalIndent(cniConfigMap, "", "  ")
	if err != nil {
		return nil, err
	}
	cniConfig = append(cniConfig, "\n"...)
	return cniConfig, nil
}

// Write atomically by writing to a temporary file in the same directory then renaming
func atomicWrite(path string, data []byte, mode os.FileMode) (err error) {
	tmpFile, err := ioutil.TempFile(filepath.Dir(path), filepath.Base(path)+".tmp.")
	if err != nil {
		return
	}
	defer func() {
		if exists(tmpFile.Name()) {
			if rmErr := os.Remove(tmpFile.Name()); rmErr != nil {
				if err != nil {
					err = errors.Wrap(err, rmErr.Error())
				} else {
					err = rmErr
				}
			}
		}
	}()

	if err = os.Chmod(tmpFile.Name(), mode); err != nil {
		return
	}

	_, err = tmpFile.Write(data)
	if err != nil {
		if closeErr := tmpFile.Close(); closeErr != nil {
			err = errors.Wrap(err, closeErr.Error())
		}
		return
	}

	tmpFile.Sync()
	if err = tmpFile.Close(); err != nil {
		return
	}

	err = os.Rename(tmpFile.Name(), path)
	return
}

// Check whether the file exists
func exists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}
