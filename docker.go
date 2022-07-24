package pgmock

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// TODO(win): connect to docker socket directly, instead of execute docker client cli

const pgPass string = "postgres"

func DockerAvailable() bool {
	_, err := exec.CommandContext(bgCtx, "docker", "info").Output()
	return err == nil
}

func tryDockerRunPostgres(name string, version int) {
	image := "postgres:alpine"
	if version != 0 {
		image = fmt.Sprintf("postgres:%d-alpine", version)
	}
	exec.CommandContext(bgCtx,
		"docker", "create",
		"--name", name,
		"--restart", "unless-stopped",
		"-l", dockerLabel,
		"-p", "5432",
		"-e", "POSTGRES_PASSWORD="+pgPass,
		image,
	).Output()
	exec.CommandContext(bgCtx, "docker", "start", name).Output()
}

func tryDockerRm(name string) {
	exec.CommandContext(bgCtx, "docker", "rm", "-fv", name).Output()
}

func dockerInspectHostPortPostgres(name string) (string, error) {
	out, err := exec.CommandContext(bgCtx,
		"docker", "inspect", name,
		"-f", `{{ with (index (index .NetworkSettings.Ports "5432/tcp") 0) }}{{ .HostIp }}#{{ .HostPort }}{{ end }}`,
	).Output()
	if err != nil {
		return "", fmt.Errorf("cannot get host and port of postgres container")
	}

	parts := strings.Split(strings.TrimSpace(string(out)), "#")

	if parts[0] == "0.0.0.0" || parts[0] == "::" {
		parts[0] = "localhost"
	}

	return net.JoinHostPort(parts[0], parts[1]), nil
}
