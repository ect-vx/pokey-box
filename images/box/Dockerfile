# pokey/box

FROM ubuntu:24.04

# TODO кастомные пакеты, подтягиваемые из файла
RUN apt-get update && apt-get install -y \
    xserver-xorg-video-dummy \
    xfce4 \
    xfce4-goodies \
    dbus-x11

ENV DISPLAY=:99

COPY ./xorg.conf /etc/X11/xorg.conf

CMD ["sh", "-c", "while [ ! -S /tmp/.X11-unix/X99 ]; do sleep 0.5; done && startxfce4"]