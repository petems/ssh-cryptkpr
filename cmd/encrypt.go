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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
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

		serverPassword, err := ReadKeyFromStdin("Enter Server Password:")

		if err != nil {
			return fmt.Errorf("prompt failed %v", err)
		}

		encryptPassword, err := ReadKeyFromStdin("Enter Encryption Password:")

		if err != nil {
			return fmt.Errorf("prompt failed %v", err)
		}

		b, err := serverPassword.Open()
		if err != nil {
			return fmt.Errorf("failed accessing server password: %w", err)
		}
		defer b.Destroy()

		c, err := encryptPassword.Open()
		if err != nil {
			return fmt.Errorf("failed accessing encryption password: %w", err)
		}
		defer c.Destroy()

		encryptedValue, err := Encrypt(Encrypttask{value: string(b.Bytes()), password: string(c.Bytes())})

		if err != nil {
			return fmt.Errorf("encryption failed %v", err)
		}

		base64Encryptedvalue := Base64Encode(encryptedValue)

		viper.Set(fmt.Sprintf("servers.%s.password", serverName), fmt.Sprintf("ENC[%s]", base64Encryptedvalue))

		err = viper.WriteConfigAs(viper.ConfigFileUsed())

		if err != nil {
			return fmt.Errorf("write config failed %v", err)
		}

		return nil

	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.PersistentFlags().String("server", "", "The server you want to encrypt and set the password for")
}
