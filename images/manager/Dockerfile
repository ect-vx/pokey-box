# pokey/manager
FROM ubuntu:24.04

# TODO кастомные пакеты, подтягиваемые из файла
RUN apt-get update && apt-get install -y \
    tightvncserver

ENV DISPLAY=:99

EXPOSE 5900


CMD ["Xvnc", ":99", "-geometry", "1280x720", "-depth", "8", "-rfbport", "5900", "-alwaysshared", "-deferupdate", "5"]


