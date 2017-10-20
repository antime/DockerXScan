package main

import(
	"io/ioutil"
	"log"
	"flag"
	// Register extensions.
	_ "github.com/MXi4oyu/DockerXScan/featurefmt/apk"
	_ "github.com/MXi4oyu/DockerXScan/featurefmt/rpm"
	_ "github.com/MXi4oyu/DockerXScan/featurefmt/dpkg"
	_ "github.com/MXi4oyu/DockerXScan/featurens/alpinerelease"
	_ "github.com/MXi4oyu/DockerXScan/featurens/aptsources"
	_ "github.com/MXi4oyu/DockerXScan/featurens/lsbrelease"
	_ "github.com/MXi4oyu/DockerXScan/featurens/osrelease"
	_ "github.com/MXi4oyu/DockerXScan/featurens/redhatrelease"
	"fmt"
	"os"
	"github.com/MXi4oyu/DockerXScan/database"
	"os/signal"
	"github.com/fatih/color"

	"github.com/MXi4oyu/DockerXScan/analyzeimages"
)


var (
	flagEndpoint        = flag.String("endpoint", "http://127.0.0.1:6060", "Address to DockerXScan API")
	flagMyAddress       = flag.String("my-address", "127.0.0.1", "Address from the point of view of DockerXScan")
	flagMinimumSeverity = flag.String("minimum-severity", "Negligible", "Minimum severity of vulnerabilities to show (Unknown, Negligible, Low, Medium, High, Critical, Defcon1)")
	flagColorMode       = flag.String("color", "auto", "Colorize the output (always, auto, never)")
)

func initMain() int {

	// Parse command-line arguments.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] image-id\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if len(flag.Args()) != 1 {
		flag.Usage()
		return 1
	}
	imageName := flag.Args()[0]

	minSeverity, err := database.NewSeverity(*flagMinimumSeverity)
	if err != nil {
		flag.Usage()
		return 1
	}

	if *flagColorMode == "never" {
		color.NoColor = true
	} else if *flagColorMode == "always" {
		color.NoColor = false
	}

	// Create a temporary folder.
	tmpPath, err := ioutil.TempDir("", "analyze-local-image-")
	if err != nil {
		log.Fatalf("Could not create temporary folder: %s", err)
	}
	defer os.RemoveAll(tmpPath)

	// Intercept SIGINT / SIGKILl signals.
	interrupt := make(chan os.Signal)
	signal.Notify(interrupt, os.Interrupt, os.Kill)

	// Analyze the image.
	analyzeCh := make(chan error, 1)
	go func() {
		analyzeCh <- analyzeimages.AnalyzeLocalImage(imageName, minSeverity, *flagEndpoint, *flagMyAddress, tmpPath)
	}()

	select {
	case <-interrupt:
		return 130
	case err := <-analyzeCh:
		if err != nil {
			log.Print(err)
			return 1
		}
	}
	return 0
}

func main()  {

	os.Exit(initMain())

}