CGO_ENABLED=0 go build
docker build -t rtop:latest .
k3d image import rtop:latest --cluster wb
