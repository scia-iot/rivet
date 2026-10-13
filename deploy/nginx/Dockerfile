FROM node:24-trixie-slim@sha256:8ec5d7557396cfe32d21c3f9c13072355ceab22b584578ca4bb28af31120cffe AS build
WORKDIR /opt/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund --legacy-peer-deps=false
COPY frontend/index.html frontend/tsconfig*.json frontend/vite.config.ts ./
COPY frontend/src ./src
COPY frontend/public ./public
RUN npm run build:container
FROM nginx:stable-trixie@sha256:0aa2d81d65bc0cac0407e738b8f07d312c8685a84225fcb4db7bcbdd8c9bdf11
# These optional modules are not loaded by the application configuration.
RUN apt-get purge --yes --no-download libxml2 libxslt1.1 nginx-module-njs nginx-module-xslt \
    && case "$(dpkg-query -W -f='${db:Status-Status}' libxml2 2>/dev/null)" in ""|not-installed) ;; *) exit 1 ;; esac \
    && xml_libraries="$(find /usr/lib -name 'libxml2.so*' -print -quit)" \
    && test -z "$xml_libraries" \
    && nginx -v \
    && curl --version
COPY --from=build /opt/frontend/dist /usr/share/nginx/html
COPY deploy/nginx/container.conf /etc/nginx/nginx.conf
COPY deploy/containers/web_entrypoint.sh /opt/container/web_entrypoint.sh
USER 101:101
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD ["curl", "--fail", "--silent", "--output", "/dev/null", "http://127.0.0.1:8080/healthz"]
ENTRYPOINT ["/bin/sh", "/opt/container/web_entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
