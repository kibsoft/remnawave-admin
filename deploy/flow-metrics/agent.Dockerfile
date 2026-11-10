# Preserve the tested bundled nDPId/BPF runtime.
FROM ghcr.io/case211/remnawave-admin-node-agent@sha256:37d447800de1a4220ee6033c70f07d4adb4929e5c3fb6108187b9c5a73e83b30
COPY node-agent/src/ /app/src/
