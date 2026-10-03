ARG ENDPOINT_IMAGE
FROM ${ENDPOINT_IMAGE}
ENV LD_LIBRARY_PATH=/neqo/lib
COPY bin /neqo/bin/
COPY lib /neqo/lib/
COPY interop.sh /neqo/interop.sh
RUN test -s /neqo/interop.sh && chmod +x /neqo/interop.sh
ENTRYPOINT ["/neqo/interop.sh"]
