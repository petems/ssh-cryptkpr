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

	"github.com/helloyi/go-sshclient"
	sshc "github.com/helloyi/go-sshclient"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

// sshCmd represents the ssh command
var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		serverName, _ := cmd.Flags().GetString("server")

		if err := viper.ReadInConfig(); err == nil {
			fmt.Println("Using config file:", viper.ConfigFileUsed())
		} else {
			return err
		}

		decryptPassword, err := ReadKeyFromStdin("Enter Decryption password:")
		if err != nil {
			return err
		}

		encryptedValue := viper.GetString(fmt.Sprintf("servers.%s.password", serverName))

		encryptedValueStripped := between(encryptedValue, "ENC[", "]")

		base64Encryptedvalue, err := Base64Decode(encryptedValueStripped)

		if err != nil {
			return fmt.Errorf("base64 decoding failed %v", err)
		}

		b, err := decryptPassword.Open()
		if err != nil {
			return fmt.Errorf("failed accessing keyring passphrase: %w", err)
		}
		defer b.Destroy()

		decryptedValue, err := Decrypt(Encrypttask{value: base64Encryptedvalue, password: string(b.Bytes())})

		if err != nil {
			return fmt.Errorf("decryption failed %v", err)
		}

		sshHost := viper.GetString(fmt.Sprintf("servers.%s.host", serverName))
		sshPort := viper.GetString(fmt.Sprintf("servers.%s.port", serverName))
		sshUser := viper.GetString(fmt.Sprintf("servers.%s.user", serverName))

		client, err := sshc.DialWithPasswd(fmt.Sprintf("%s:%s", sshHost, sshPort), sshUser, decryptedValue)
		if err != nil {
			return err
		}
		// default terminal
		if err := client.Terminal(nil).Start(); err != nil {
			return err
		}

		// with a terminal config
		config := &sshclient.TerminalConfig{
			Term:   "xterm",
			Height: 40,
			Weight: 80,
			Modes: ssh.TerminalModes{
				ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
				ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
			},
		}
		if err := client.Terminal(config).Start(); err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(sshCmd)

	sshCmd.PersistentFlags().String("server", "", "The server you want connect to")
}
