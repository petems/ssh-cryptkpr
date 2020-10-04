/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"

	"github.com/ghodss/yaml"
	"github.com/gookit/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Print current config",
	Long:  `Displays current cryptkpr configuration.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// If a config file is found, read it in.
		if err := viper.ReadInConfig(); err == nil {
			fmt.Println("Using config file:", viper.ConfigFileUsed())
		} else {
			return err
		}

		servers := viper.GetStringMap("servers")

		if len(servers) == 0 {
			fmt.Println(color.Red.Render("No servers Found in config"))
			return nil
		} else {
			for key, element := range servers {
				fmt.Println("Server:", key)
				data, err := yaml.Marshal(element)
				if err != nil {
					fmt.Printf("marshal failed: %s", err)
				}
				fmt.Printf(string(data))
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
