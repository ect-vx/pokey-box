
// stub file with MVP functions
// TODO: осознать и переработать "как положено"

use std::fmt::Error;

// helpers.rs
use bollard::Docker;
use bollard::container::{CreateContainerOptions, Config, StartContainerOptions};
use bollard::models::{HostConfig, PortBinding, Mount, MountTypeEnum};
use std::collections::HashMap;


const IMG_MGR:   &str = "pokey-mgr:latest";
const IMG_BOX:   &str = "pokey-box:latest";
const IMG_SNIFF: &str = "pokey-sniff:latest";

const NET_MGR_TEMPLATE:  &str = "mgr_net_{}";
const NET_BOX_TEMPLATE:  &str = "box_net_{}";

const XORG_CONF_PATH: &str = "./sandbox_config/xorg.conf";
const LOGS_PATH:      &str = "./logs";


pub async fn init_box(uuid: String) {
    let docker = Docker::connect_with_local_defaults().unwrap();

    let net_mgr  = NET_MGR_TEMPLATE.replace("{}", &uuid);
    let net_box  = NET_BOX_TEMPLATE.replace("{}", &uuid);

    let name_mgr   = format!("pokey-mgr-{}",   uuid);
    let name_box   = format!("pokey-box-{}",   uuid);
    let name_sniff = format!("pokey-sniff-{}", uuid);

    let vol_x11 = format!("x11-socket-{}", uuid);

    // --- Сети ---
    docker.create_network(bollard::network::CreateNetworkOptions {
        name: net_mgr.as_str(),
        driver: "bridge",
        ..Default::default()
    }).await.unwrap();

    docker.create_network(bollard::network::CreateNetworkOptions {
        name: net_box.as_str(),
        driver: "bridge",
        ..Default::default()
    }).await.unwrap();

    // --- Volume для X11 сокета ---
    docker.create_volume(bollard::volume::CreateVolumeOptions {
        name: vol_x11.as_str(),
        ..Default::default()
    }).await.unwrap();


    // --- КОРОБКА (pokey-box) ---
    let box_config = Config {
        image: Some(IMG_BOX),
        host_config: Some(HostConfig {
            mounts: Some(vec![
                // xorg.conf только для чтения
                Mount {
                    target: Some("/etc/X11/xorg.conf".to_string()),
                    source: Some(XORG_CONF_PATH.to_string()),
                    typ: Some(MountTypeEnum::BIND),
                    read_only: Some(true),
                    ..Default::default()
                },
                // X11 сокет
                Mount {
                    target: Some("/tmp/.X11-unix".to_string()),
                    source: Some(vol_x11.clone()),
                    typ: Some(MountTypeEnum::VOLUME),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }),
        ..Default::default()
    };

    docker.create_container(
        Some(CreateContainerOptions { name: name_box.as_str() }), // , platform: None
        box_config,
    ).await.unwrap();

    docker.connect_network(&net_box, bollard::network::ConnectNetworkOptions {
        container: name_box.as_str(),
        ..Default::default()
    }).await.unwrap();

    docker.start_container(&name_box, None::<StartContainerOptions<String>>).await.unwrap();
    println!("Запущен box: {}", name_box);


    // --- СНИФФЕР (pokey-sniff) ---
    // network_mode: container:<box> — шарит сетевой интерфейс коробки
    let sniff_config = Config {
        image: Some(IMG_SNIFF),
        host_config: Some(HostConfig {
            cap_add: Some(vec!["NET_ADMIN".to_string()]),
            network_mode: Some(format!("container:{}", name_box)),
            ..Default::default()
        }),
        ..Default::default()
    };

    docker.create_container(
        Some(CreateContainerOptions { name: name_sniff.as_str()}), // , platform: None
        sniff_config,
    ).await.unwrap();

    docker.start_container(&name_sniff, None::<StartContainerOptions<String>>).await.unwrap();
    println!("Запущен sniff: {}", name_sniff);


    // --- МЕНЕДЖЕР / VNC (pokey-mgr) ---
    let mut port_bindings = HashMap::new();
    port_bindings.insert(
        "5900/tcp".to_string(),
        Some(vec![PortBinding {
            host_ip:   Some("0.0.0.0".to_string()),
            host_port: Some("5900".to_string()),
        }]),
    );

    let mgr_config = Config {
        image: Some(IMG_MGR),
        env: Some(vec!["DISPLAY=:99"]),
        host_config: Some(HostConfig {
            cap_add: Some(vec!["NET_ADMIN".to_string()]),
            port_bindings: Some(port_bindings),
            mounts: Some(vec![
                // X11 сокет — read/write
                Mount {
                    target: Some("/tmp/.X11-unix".to_string()),
                    source: Some(vol_x11.clone()),
                    typ: Some(MountTypeEnum::VOLUME),
                    read_only: Some(false),
                    ..Default::default()
                },
                // Папка логов
                Mount {
                    target: Some("/logs".to_string()),
                    source: Some(LOGS_PATH.to_string()),
                    typ: Some(MountTypeEnum::BIND),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }),
        ..Default::default()
    };

    docker.create_container(
        Some(CreateContainerOptions { name: name_mgr.as_str()}), // , platform: None
        mgr_config,
    ).await.unwrap();

    docker.connect_network(&net_mgr, bollard::network::ConnectNetworkOptions {
        container: name_mgr.as_str(),
        ..Default::default()
    }).await.unwrap();

    docker.start_container(&name_mgr, None::<StartContainerOptions<String>>).await.unwrap();
    println!("Запущен mgr: {}", name_mgr);
    todo!()
}

pub async fn kill_box() -> Result<i32, Error> {
    todo!();
}

pub async fn kill_analysis() -> Result<i32, Error> {
    todo!();
}