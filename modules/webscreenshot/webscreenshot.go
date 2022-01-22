package webscreenshot

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func takeScreenshotCmd(rendererPath string, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, rendererPath, args...)
	if err := cmd.Start(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("The renderer timed out.")
		}

		return err
	}

	return nil
}

func getFilenameFromURL(url string) string {
	filename := strings.ReplaceAll(url, "://", "_")
	re := regexp.MustCompile(`[^\w\-_\. ]`)
	filename = re.ReplaceAllString(filename, "_")

	return filename + ".png"
}

func TakeScreenshot(url string, renderer string, rendererPath string, outputDirectory string) (string, error) {
	screenshot := filepath.Join(outputDirectory, getFilenameFromURL(url))
	windowSize := "1200,800"
	renderer = strings.ToLower(renderer)
	args := []string{}

	if renderer == "chrome" || renderer == "chromium" {
		// https://developers.google.com/web/updates/2017/04/headless-chrome
		args = append(args, []string{
			"--headless",
			"--disable-gpu",
			"--hide-scrollbars",
			"--incognito",
			"--allow-running-insecure-content",
			"--ignore-certificate-errors",
			"--ignore-urlfetcher-cert-requests",
			"--reduce-security-for-testing",
			"--no-sandbox",
			"--disable-crash-reporter",
		}...)
	} else if renderer == "firefox" {
		// https://developer.mozilla.org/en-US/docs/Mozilla/Firefox/Headless_mode
		args = append(args, []string{
			// "--new-instance",
			// "--headless" // You can omit -headless when using --screenshot
		}...)
	} else {
		return "", fmt.Errorf("The renderer \"%s\" is invalid, please use \"chrome\", \"chromium\" or \"firefox\".", renderer)
	}

	args = append(args, []string{
		"--screenshot=" + screenshot,
		"--window-size=" + windowSize,
		url,
	}...)

	if err := takeScreenshotCmd(rendererPath, args); err != nil {
		return "", err
	}

	return screenshot, nil
}
