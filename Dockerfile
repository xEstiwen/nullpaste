FROM scratch

COPY nullpaste /nullpaste
COPY web/static /static

EXPOSE 8080

ENTRYPOINT ["/nullpaste"]
CMD ["--addr", ":8080", "--db-path", "/data/nullpaste.db"]
