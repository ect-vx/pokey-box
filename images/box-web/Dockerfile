FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    software-properties-common \
    ca-certificates \
    && add-apt-repository ppa:xtradeb/apps -y

# TODO кастомные пакеты, подтягиваемые из файла
RUN apt-get update && apt-get install -y \
    xfce4 \
    xfce4-terminal \
    mousepad \
    chromium \
    dbus-x11 \
    libgl1-mesa-dri \
    && rm -rf /var/lib/apt/lists/*


ARG USER_UID=1100
ARG USER_GID=1100

RUN groupadd --gid $USER_GID appuser \
    && useradd --uid $USER_UID --gid $USER_GID --create-home --shell /bin/bash appuser

ENV DISPLAY=:99
ENV SSLKEYLOGFILE=/home/appuser/sslkeys.log

COPY ./xorg.conf /etc/X11/xorg.conf

USER appuser
WORKDIR /home/appuser

RUN mkdir -p /home/appuser/.config/autostart

RUN echo '[Desktop Entry]\n\
Type=Application\n\
Exec=sh -c "chromium --no-sandbox --disable-gpu --start-maximized \$START_URL"\n\
Hidden=false\n\
NoDisplay=false\n\
X-GNOME-Autostart-enabled=true\n\
Name=ChromiumAuto\n\
Comment=Start Chromium on XFCE Startup\n' > /home/appuser/.config/autostart/chromium.desktop



CMD ["sh", "-c", "while [ ! -S /tmp/.X11-unix/X99 ]; do sleep 0.5; done && exec dbus-launch --exit-with-session startxfce4"]
