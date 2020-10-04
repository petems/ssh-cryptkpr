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
	"strings"

	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		serverName, _ := cmd.Flags().GetString("server")
		fmt.Println("encrypt called for server:", serverName)

		if err := viper.ReadInConfig(); err == nil {
			fmt.Println("Using config file:", viper.ConfigFileUsed())
		} else {
			return err
		}

		decryptPasswordPrompt := promptui.Prompt{
			Label: "decryption Password",
			Mask:  '*',
		}

		decryptPassword, err := decryptPasswordPrompt.Run()

		if err != nil {
			return fmt.Errorf("prompt failed %v", err)
		}

		encryptedValue := viper.GetString(fmt.Sprintf("servers.%s.password", serverName))

		encryptedValueStripped := between(encryptedValue, "ENC[", "]")

		base64Encryptedvalue, err := Base64Decode(encryptedValueStripped)

		if err != nil {
			return fmt.Errorf("base64 decoding failed %v", err)
		}

		decryptedValue, err := Decrypt(Encrypttask{value: base64Encryptedvalue, password: decryptPassword})

		if err != nil {
			return fmt.Errorf("decryption failed %v", err)
		}

		fmt.Println(decryptedValue)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)

	decryptCmd.PersistentFlags().String("server", "", "The server you want to encrypt and set the password for")
}

func between(value string, a string, b string) string {
	// Get substring between two strings.
	posFirst := strings.Index(value, a)
	if posFirst == -1 {
		return ""
	}
	posLast := strings.Index(value, b)
	if posLast == -1 {
		return ""
	}
	posFirstAdjusted := posFirst + len(a)
	if posFirstAdjusted >= posLast {
		return ""
	}
	return value[posFirstAdjusted:posLast]
}
