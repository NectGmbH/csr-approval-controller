FROM alpine:3.8

COPY ./csr-approval-controller /bin/csr-approval-controller

ENTRYPOINT [ "/bin/csr-approval-controller" ]