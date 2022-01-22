package webscreenshot

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	ws "github.com/vincd/savoir/modules/webscreenshot"
)

var Command = &cobra.Command{
	Use:   "webscreenshot",
	Short: "Take a screenshot of a URL.",
	Long:  `Take a screenshot of a URL using Chrome or Firefox headless mode. Save the screenshot to the output directory.`,
}

func init() {
	var url string
	var urlFile string
	var urls []string
	var renderer string
	var rendererPath string
	var outputDirectory string

	Command.Args = func(cmd *cobra.Command, args []string) error {
		if len(url) > 0 {
			if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
				return fmt.Errorf("URL parameter must start with http:// or https://.")
			}

			urls = append(urls, url)
		} else if len(urlFile) > 0 {
			if _, err := os.Stat(urlFile); os.IsNotExist(err) {
				return fmt.Errorf("The URL file \"%s\" does not exist.", urlFile)
			}

			file, err := os.Open(urlFile)
			if err != nil {
				return fmt.Errorf("Cannot open URL file: %s", err)
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				urls = append(urls, scanner.Text())
			}
		} else {
			return fmt.Errorf("You must specify an URL or a path to a file containing URL.")
		}

		if len(outputDirectory) == 0 {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil
			}

			outputDirectory = home
		}

		if _, err := os.Stat(outputDirectory); os.IsNotExist(err) {
			return fmt.Errorf("The output directory \"%s\" does not exist.", outputDirectory)
		}

		if renderer != "chrome" && renderer != "chromium" && renderer != "firefox" {
			return fmt.Errorf("Invalid renderer \"%s\", must be one of chrome, chromium or firefox.", renderer)
		}

		if _, err := os.Stat(rendererPath); os.IsNotExist(err) {
			return fmt.Errorf("The renderer path \"%s\" does not exist.", rendererPath)
		}

		return nil
	}
	Command.RunE = func(cmd *cobra.Command, args []string) error {
		for _, url := range urls {
			path, err := ws.TakeScreenshot(url, renderer, rendererPath, outputDirectory)
			if err != nil {
				fmt.Printf("Cannot make a screenshot of \"%s\": %s", url, err)
			} else {
				fmt.Printf("Screenshot written to: %s\n", path)
			}
		}

		return nil
	}

	Command.Flags().StringVarP(&url, "url", "u", "", "URL to screenshot starting with http:// or https://")
	Command.Flags().StringVarP(&urlFile, "url-file", "U", "", "Path of a file containing a valid URL on each line")
	Command.Flags().StringVarP(&outputDirectory, "output", "o", "", "Output directory to save the screenshot (default is $HOME)")
	Command.Flags().StringVarP(&renderer, "renderer", "r", "", "Set the renderer: chrome, chromium or firefox")
	Command.Flags().StringVarP(&rendererPath, "renderer-path", "p", "", "Set the renderer path")
}
