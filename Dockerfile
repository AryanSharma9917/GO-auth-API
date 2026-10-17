FROM golang:1.27.2-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/go-auth-api .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/go-auth-api /go-auth-api
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/go-auth-api"]
