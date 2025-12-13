package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const flattenFileName = ".flatten"

type flattenProfile struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

type flattenFile struct {
	Include  []string                  `yaml:"include"`
	Exclude  []string                  `yaml:"exclude"`
	Profiles map[string]flattenProfile `yaml:"profiles"`
}

type flattenRuleSet struct {
	include []string
	exclude []string
}

func readFlattenFile(path string, profile string) (*flattenRuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg flattenFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse flatten file: %w", err)
	}

	include := append([]string{}, cfg.Include...)
	exclude := append([]string{}, cfg.Exclude...)

	if len(cfg.Profiles) > 0 {
		if prof, ok := cfg.Profiles[profile]; ok {
			include = append(include, prof.Include...)
			exclude = append(exclude, prof.Exclude...)
		} else if prof, ok := cfg.Profiles["default"]; ok {
			include = append(include, prof.Include...)
			exclude = append(exclude, prof.Exclude...)
		}
	}

	return &flattenRuleSet{
		include: include,
		exclude: exclude,
	}, nil
}
