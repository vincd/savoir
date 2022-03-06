package scanner

import (
	"fmt"
	"net"
	"sync"
)

const (
	ProtocolTcp string = "tcp"
	ProtocolUdp string = "udp"
)

const (
	PortOpen     string = "Open"
	PortFiltered string = "Filtered"
	PortTimeout  string = "Timeout"
	PortClosed   string = "Closed"
)

type PortStatus struct {
	Protocol string `json:"protocol"`
	IP       string `json:"ip"`
	Port     uint16 `json:"port"`
	State    string `json:"state"`
}

type PortScanner interface {
	ScanPort(ip net.IP, port uint16) (PortStatus, error)
}

type workerJob struct {
	ip   net.IP
	port uint16
	done chan struct{}
}

func ScanPorts(scanner PortScanner, workers int, ip net.IP, ports []uint16) ([]PortStatus, error) {
	// WaitingGroup to ensure all ports are scanned
	wgPorts := &sync.WaitGroup{}
	// WaitingGroup to ensure all workers are done
	wgWorkers := &sync.WaitGroup{}

	// Channel for workers
	workerChan := make(chan workerJob, workers)

	// Results channel to collect status from worker
	resultsChan := make(chan PortStatus)
	results := make([]PortStatus, 0)
	go func() {
		// TODO: handle timeout etc

		for status := range resultsChan {
			results = append(results, status)
		}
	}()

	// Create workers
	for i := 0; i < workers; i++ {
		wgWorkers.Add(1)
		go func() {
			for job := range workerChan {
				status, err := scanner.ScanPort(job.ip, job.port)
				if err != nil {
					// TODO: use a custom channel for errors
					fmt.Printf("an error occured on %s:%d: %s\n", job.ip, job.port, err)
				} else {
					resultsChan <- status
				}
				close(job.done)
			}

			wgWorkers.Done()
		}()
	}

	// For each ports add a function to create the new workerJob
	for _, port := range ports {
		wgPorts.Add(1)
		go func(p uint16, wg *sync.WaitGroup) {
			// Create a new channel for the worker to indicate the end of the job
			done := make(chan struct{})

			// Pass to a work the new job (with the done channel)
			workerChan <- workerJob{
				ip:   ip,
				port: p,
				done: done,
			}

			// Wait for the work to end the scanning and update the WaitingGroup
			<-done
			wg.Done()
		}(port, wgPorts)
	}

	// Wait for all ports to be scanned
	wgPorts.Wait()
	// Close the worker channel when it's done
	close(workerChan)
	// Wait for all worker to end
	wgWorkers.Wait()
	// Close the results channels
	close(resultsChan)

	return results, nil
}
