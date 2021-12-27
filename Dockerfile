FROM busybox
ADD k8s-webhook /
RUN mkdir /certs
RUN mkdir -p /configs/inject
RUN mkdir -p /configs/core
CMD ["./k8s-webhook"]

